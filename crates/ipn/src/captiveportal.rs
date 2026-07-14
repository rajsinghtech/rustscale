//! Captive-portal detection driven by connectivity health warnings.

use std::time::Duration;

use rustscale_health::{
    Tracker, WARN_CAPTIVE_PORTAL, WARN_CONTROL, WARN_DERP_HOME, WARN_DERP_NO_REGION,
    WARN_DERP_TIMEOUT, WARN_IPV4, WARN_IPV6, WARN_MAP_RESPONSE_TIMEOUT, WARN_NOT_IN_MAP_POLL,
    WARN_NO_DERP_CONNECTION, WARN_PRODUCTIVITY, WARN_TLS_CONNECTION_FAILED, WARN_UDP,
};
use rustscale_netcheck::Detector;
use rustscale_tailcfg::DERPMap;
use tokio::sync::{oneshot, watch};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const DETECTION_DELAY: Duration = Duration::from_secs(2);

/// Health warning IDs that indicate connectivity may be impaired.
///
/// Captive-portal itself is intentionally absent: including it would make a
/// positive result schedule another detection forever.
const CONNECTIVITY_WARNABLES: &[&str] = &[
    WARN_CONTROL,
    WARN_DERP_HOME,
    WARN_PRODUCTIVITY,
    WARN_UDP,
    WARN_IPV4,
    WARN_IPV6,
    WARN_DERP_NO_REGION,
    WARN_NOT_IN_MAP_POLL,
    WARN_MAP_RESPONSE_TIMEOUT,
    WARN_NO_DERP_CONNECTION,
    WARN_DERP_TIMEOUT,
    WARN_TLS_CONNECTION_FAILED,
];

/// Watches health warnings and probes for a captive portal after connectivity
/// becomes impaired.
pub struct CaptivePortalWatcher {
    stop: Option<oneshot::Sender<()>>,
}

impl CaptivePortalWatcher {
    /// Start the watcher in a background task.
    pub fn spawn(
        health: Tracker,
        detector: Detector,
        derp_map: watch::Receiver<Option<DERPMap>>,
        preferred_derp: watch::Receiver<i32>,
    ) -> Self {
        let (stop_tx, mut stop_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            let mut detection_at = None;
            let mut connectivity_was_impacted = false;

            loop {
                tokio::select! {
                    biased;
                    _ = &mut stop_rx => return,
                    _ = ticker.tick() => {}
                }

                let connectivity_impacted = health
                    .current_warnings()
                    .iter()
                    .any(|warning| CONNECTIVITY_WARNABLES.contains(&warning.id.as_str()));

                if !connectivity_impacted {
                    detection_at = None;
                    connectivity_was_impacted = false;
                    health.set_healthy(WARN_CAPTIVE_PORTAL);
                    continue;
                }

                if !connectivity_was_impacted {
                    detection_at = Some(tokio::time::Instant::now() + DETECTION_DELAY);
                    connectivity_was_impacted = true;
                }

                if detection_at.is_some_and(|at| tokio::time::Instant::now() >= at) {
                    detection_at = None;
                    let derp_map = derp_map.borrow().clone();
                    let preferred_derp = *preferred_derp.borrow();
                    match detector
                        .detect_bool(derp_map.as_ref(), preferred_derp)
                        .await
                    {
                        Some(true) => health.set_unhealthy(
                            WARN_CAPTIVE_PORTAL,
                            "This network requires you to log in using your web browser.",
                        ),
                        Some(false) => health.set_healthy(WARN_CAPTIVE_PORTAL),
                        None => {}
                    }
                }
            }
        });
        Self {
            stop: Some(stop_tx),
        }
    }

    /// Stop the background watcher now rather than waiting for drop.
    pub fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl Drop for CaptivePortalWatcher {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rustscale_health::{WARN_CAPTIVE_PORTAL, WARN_CONTROL};
    use rustscale_netcheck::Detector;
    use rustscale_tailcfg::{DERPNode, DERPRegion};

    use super::*;

    fn derp_map() -> DERPMap {
        let mut regions = BTreeMap::new();
        regions.insert(
            1,
            DERPRegion {
                RegionID: 1,
                Nodes: Some(vec![DERPNode {
                    RegionID: 1,
                    IPv4: "127.0.0.1".into(),
                    CanPort80: true,
                    ..Default::default()
                }]),
                ..Default::default()
            },
        );
        DERPMap {
            Regions: regions,
            ..Default::default()
        }
    }

    async fn wait_for(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(4), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("condition should become true");
    }

    #[tokio::test]
    async fn watcher_schedules_on_connectivity_warning() {
        let dials = Arc::new(AtomicUsize::new(0));
        let detector_dials = dials.clone();
        let detector = Detector::with_dialer(move |_, _| {
            detector_dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(std::io::Error::other("test dial")) })
        });
        let health = Tracker::new();
        let (_map_tx, map_rx) = watch::channel(Some(derp_map()));
        let (_preferred_tx, preferred_rx) = watch::channel(1);
        let _watcher = CaptivePortalWatcher::spawn(health.clone(), detector, map_rx, preferred_rx);

        health.set_unhealthy(WARN_CONTROL, "control unavailable");
        wait_for(|| dials.load(Ordering::SeqCst) > 0).await;
    }

    #[tokio::test]
    async fn watcher_clears_on_connectivity_restored() {
        let health = Tracker::new();
        let (_map_tx, map_rx) = watch::channel(None);
        let (_preferred_tx, preferred_rx) = watch::channel(0);
        let _watcher =
            CaptivePortalWatcher::spawn(health.clone(), Detector::default(), map_rx, preferred_rx);

        health.set_unhealthy(WARN_CONTROL, "control unavailable");
        health.set_unhealthy(WARN_CAPTIVE_PORTAL, "portal");
        health.set_healthy(WARN_CONTROL);
        wait_for(|| !health.is_unhealthy(WARN_CAPTIVE_PORTAL)).await;
    }

    #[tokio::test]
    async fn watcher_does_not_loop_self_referentially() {
        let dials = Arc::new(AtomicUsize::new(0));
        let detector_dials = dials.clone();
        let detector = Detector::with_dialer(move |_, _| {
            detector_dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(std::io::Error::other("should not dial")) })
        });
        let health = Tracker::new();
        let (_map_tx, map_rx) = watch::channel(Some(derp_map()));
        let (_preferred_tx, preferred_rx) = watch::channel(1);
        let _watcher = CaptivePortalWatcher::spawn(health.clone(), detector, map_rx, preferred_rx);

        health.set_unhealthy(WARN_CAPTIVE_PORTAL, "portal");
        tokio::time::sleep(DETECTION_DELAY + POLL_INTERVAL + Duration::from_millis(200)).await;
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }
}
