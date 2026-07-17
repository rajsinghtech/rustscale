// Command go_extract inventories selected public compatibility surfaces from a
// pinned tailscale.com module using only the Go standard library.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type item struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Owner     string   `json:"owner,omitempty"`
	Signature string   `json:"signature"`
	Source    []string `json:"source"`
}

type route struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Handler   string   `json:"handler"`
	Methods   []string `json:"methods"`
	SchemaIDs []string `json:"schema_ids"`
	Source    []string `json:"source"`
}

type output struct {
	Tsnet struct {
		Items []item `json:"items"`
	} `json:"tsnet"`
	LocalAPI struct {
		Routes []route `json:"routes"`
	} `json:"localapi"`
}

type itemAccum struct {
	kind       string
	name       string
	owner      string
	signatures map[string]bool
	sources    map[string]bool
}

type functionBody struct {
	decl   *ast.FuncDecl
	fset   *token.FileSet
	source string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run go_extract.go <tailscale-module-dir>")
		os.Exit(2)
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		fatal(err)
	}

	var result output
	result.Tsnet.Items, err = extractTsnet(root)
	if err != nil {
		fatal(err)
	}
	result.LocalAPI.Routes, err = extractLocalAPI(root)
	if err != nil {
		fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "go_extract:", err)
	os.Exit(1)
}

func goFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	sort.Strings(files)
	return files, nil
}

func parseFiles(root, subdir string) ([]*ast.File, []*token.FileSet, []string, error) {
	paths, err := goFiles(filepath.Join(root, subdir))
	if err != nil {
		return nil, nil, nil, err
	}
	var files []*ast.File
	var fsets []*token.FileSet
	var sources []string
	for _, path := range paths {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, nil, err
		}
		files = append(files, file)
		fsets = append(fsets, fset)
		sources = append(sources, filepath.ToSlash(filepath.Join(subdir, filepath.Base(path))))
	}
	return files, fsets, sources, nil
}

func extractTsnet(root string) ([]item, error) {
	files, fsets, sources, err := parseFiles(root, "tsnet")
	if err != nil {
		return nil, err
	}
	items := map[string]*itemAccum{}
	add := func(id, kind, name, owner, signature, source string) {
		a := items[id]
		if a == nil {
			a = &itemAccum{
				kind:       kind,
				name:       name,
				owner:      owner,
				signatures: map[string]bool{},
				sources:    map[string]bool{},
			}
			items[id] = a
		}
		a.signatures[normalizeSpace(signature)] = true
		a.sources[source] = true
	}

	for i, file := range files {
		fset, source := fsets[i], sources[i]
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				sig := render(fset, d.Type)
				if d.Recv == nil || len(d.Recv.List) == 0 {
					add("function:"+d.Name.Name, "function", d.Name.Name, "", "func "+d.Name.Name+strings.TrimPrefix(sig, "func"), source)
					continue
				}
				owner := receiverName(d.Recv.List[0].Type)
				if owner == "" || !ast.IsExported(owner) {
					continue
				}
				add("method:"+owner+"."+d.Name.Name, "method", d.Name.Name, owner, "func "+d.Name.Name+strings.TrimPrefix(sig, "func"), source)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						sig := "type " + s.Name.Name + " " + render(fset, s.Type)
						if _, ok := s.Type.(*ast.StructType); ok {
							// Public fields are inventoried independently below; omit
							// private implementation fields from the public type shape.
							sig = "type " + s.Name.Name + " struct"
						}
						add("type:"+s.Name.Name, "type", s.Name.Name, "", sig, source)
						extractTypeMembers(s, fset, source, add)
					case *ast.ValueSpec:
						kind := strings.ToLower(d.Tok.String())
						for n, name := range s.Names {
							if !name.IsExported() {
								continue
							}
							sig := kind + " " + name.Name
							if s.Type != nil {
								sig += " " + render(fset, s.Type)
							}
							if n < len(s.Values) {
								sig += " = " + render(fset, s.Values[n])
							}
							add(kind+":"+name.Name, kind, name.Name, "", sig, source)
						}
					}
				}
			}
		}
	}

	out := make([]item, 0, len(items))
	for id, a := range items {
		out = append(out, item{
			ID:        id,
			Kind:      a.kind,
			Name:      a.name,
			Owner:     a.owner,
			Signature: strings.Join(sortedKeys(a.signatures), " | "),
			Source:    sortedKeys(a.sources),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func extractTypeMembers(spec *ast.TypeSpec, fset *token.FileSet, source string, add func(string, string, string, string, string, string)) {
	owner := spec.Name.Name
	switch typ := spec.Type.(type) {
	case *ast.StructType:
		for _, field := range typ.Fields.List {
			for _, name := range exportedFieldNames(field) {
				add("field:"+owner+"."+name, "field", name, owner, name+" "+render(fset, field.Type), source)
			}
		}
	case *ast.InterfaceType:
		for _, field := range typ.Methods.List {
			for _, name := range field.Names {
				if name.IsExported() {
					add("method:"+owner+"."+name.Name, "method", name.Name, owner, "func "+name.Name+strings.TrimPrefix(render(fset, field.Type), "func"), source)
				}
			}
		}
	}
}

func exportedFieldNames(field *ast.Field) []string {
	var names []string
	for _, name := range field.Names {
		if name.IsExported() {
			names = append(names, name.Name)
		}
	}
	if len(field.Names) == 0 {
		name := receiverName(field.Type)
		if ast.IsExported(name) {
			names = append(names, name)
		}
	}
	return names
}

func extractLocalAPI(root string) ([]route, error) {
	files, fsets, sources, err := parseFiles(root, filepath.Join("ipn", "localapi"))
	if err != nil {
		return nil, err
	}
	functions := map[string][]functionBody{}
	registrations := map[string]map[string]bool{}
	registrationSources := map[string]map[string]bool{}

	addRegistration := func(path, handler, source string) {
		key := path + "\x00" + handler
		if registrations[key] == nil {
			registrations[key] = map[string]bool{}
			registrationSources[key] = map[string]bool{}
		}
		registrations[key][handler] = true
		registrationSources[key][source] = true
	}

	for i, file := range files {
		fset, source := fsets[i], sources[i]
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				functions[d.Name.Name] = append(functions[d.Name.Name], functionBody{d, fset, source})
				if d.Body != nil {
					ast.Inspect(d.Body, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok || calledName(call.Fun) != "Register" || len(call.Args) < 2 {
							return true
						}
						path, ok := stringLiteral(call.Args[0])
						if !ok {
							return true
						}
						handler := handlerName(call.Args[1])
						if handler != "" {
							addRegistration(path, handler, source)
						}
						return true
					})
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "handler" {
						continue
					}
					for _, value := range vs.Values {
						lit, ok := value.(*ast.CompositeLit)
						if !ok {
							continue
						}
						for _, element := range lit.Elts {
							kv, ok := element.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							path, ok := stringLiteral(kv.Key)
							handler := handlerName(kv.Value)
							if ok && handler != "" {
								addRegistration(path, handler, source)
							}
						}
					}
				}
			}
		}
	}

	var routes []route
	for key := range registrations {
		parts := strings.SplitN(key, "\x00", 2)
		path, handler := parts[0], parts[1]
		methods := map[string]bool{}
		schemas := map[string]bool{"handler." + handler: true}
		visited := map[string]bool{}
		collectHandlerFacts(handler, functions, methods, schemas, visited, 0)
		if len(methods) == 0 {
			methods["ANY"] = true
		}
		normalizedPath := path
		if strings.HasSuffix(normalizedPath, "/") {
			normalizedPath += "<suffix>"
		}
		routes = append(routes, route{
			ID:        "route:" + normalizedPath,
			Path:      normalizedPath,
			Handler:   handler,
			Methods:   sortedKeys(methods),
			SchemaIDs: sortedKeys(schemas),
			Source:    sortedKeys(registrationSources[key]),
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].ID < routes[j].ID })
	return routes, nil
}

func collectHandlerFacts(name string, functions map[string][]functionBody, methods, schemas, visited map[string]bool, depth int) {
	if visited[name] || depth > 2 {
		return
	}
	visited[name] = true
	for _, function := range functions[name] {
		if function.decl.Body == nil {
			continue
		}
		ast.Inspect(function.decl.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.SelectorExpr:
				if ident, ok := n.X.(*ast.Ident); ok && ident.Name == "httpm" && isHTTPMethod(n.Sel.Name) {
					methods[n.Sel.Name] = true
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if value, err := strconv.Unquote(n.Value); err == nil && isHTTPMethod(value) {
						methods[value] = true
					}
				}
			case *ast.CompositeLit:
				if schema := schemaName(n.Type); schema != "" {
					schemas[schema] = true
				}
			case *ast.CallExpr:
				called := calledName(n.Fun)
				if called != "" && called != name && functions[called] != nil {
					collectHandlerFacts(called, functions, methods, schemas, visited, depth+1)
				}
			}
			return true
		})
	}
}

func schemaName(expr ast.Expr) string {
	var value string
	switch e := expr.(type) {
	case *ast.Ident:
		value = e.Name
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			value = x.Name + "." + e.Sel.Name
		}
	case *ast.ArrayType:
		if nested := schemaName(e.Elt); nested != "" {
			value = nested + "[]"
		}
	case *ast.StarExpr:
		value = schemaName(e.X)
	}
	base := value
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		base = base[dot+1:]
	}
	for _, suffix := range []string{"Request", "Response", "Result", "Status", "Config", "Prefs", "Profile", "Options", "Args", "Notify", "File", "Target", "Map", "Report"} {
		if strings.HasSuffix(base, suffix) {
			return value
		}
	}
	return ""
}

func receiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverName(e.X)
	case *ast.IndexExpr:
		return receiverName(e.X)
	case *ast.IndexListExpr:
		return receiverName(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.ParenExpr:
		return receiverName(e.X)
	default:
		return ""
	}
}

func handlerName(expr ast.Expr) string {
	if selector, ok := expr.(*ast.SelectorExpr); ok {
		return selector.Sel.Name
	}
	return ""
}

func calledName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.IndexExpr:
		return calledName(e.X)
	case *ast.IndexListExpr:
		return calledName(e.X)
	default:
		return ""
	}
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

func isHTTPMethod(value string) bool {
	switch value {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	default:
		return false
	}
}

func render(fset *token.FileSet, node any) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, node); err != nil {
		return "<unprintable>"
	}
	return b.String()
}

func normalizeSpace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func sortedKeys[V ~bool](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
