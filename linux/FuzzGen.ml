(*
 * FuzzGen.ml - Fuzzing wrapper code generation for SGX ECalls/OCalls
 * 
 * This module generates fuzzing harness code that:
 * - Creates fuzz_ecall_xxx wrapper functions
 * - Creates __ocall_wrapper_xxx functions
 * - Uses DF runtime functions to obtain fuzz input
 *)

open Ast

(* Use enclave_content type from Ast.ml *)

(* ========== TypeInfo JSON Handling ========== *)

(* Global typedef mapping - maps typedef name to its actual type *)
let typedef_table : (string, string) Hashtbl.t = Hashtbl.create 128

let rec ast_ty_to_atype (tystr : string) : atype option =
  let tystr = String.trim tystr in
  if String.ends_with ~suffix:"*" tystr then
    (* Pointer type, try to extract base *)
    let base_tystr =
      String.sub tystr 0 (String.length tystr - 1) |> String.trim
    in
    match ast_ty_to_atype base_tystr with
    | Some aty -> Some (Ptr aty)
    | None -> None
  else if String.ends_with ~suffix:"]" tystr then failwith "not supported"
    (* let re = Re.Pcre.regexp {|^(.*)\[[0-9]+?\]$|} in
    match Re.exec_opt re tystr with
    | Some g -> ast_ty_to_atype (String.trim (Re.Group.get g 1))
    | None -> failwith "not a array?" *)
  else if String.starts_with ~prefix:"struct " tystr then
    Some (Struct (String.sub tystr 7 (String.length tystr - 7)))
  else if String.starts_with ~prefix:"union " tystr then
    Some (Union (String.sub tystr 6 (String.length tystr - 6)))
  else if String.starts_with ~prefix:"enum " tystr then
    Some (Enum (String.sub tystr 5 (String.length tystr - 5)))
  else
    match tystr with
    | "void" -> Some Void
    | "int" -> Some (Int { ia_signedness = Signed; ia_shortness = INone })
    | "char" -> Some (Char Signed)
    | _ -> None

(* Extract typedef information using clang AST (more reliable) *)
let update_typedef_info (header_path : string) : unit =
  if Sys.file_exists header_path then
    let cmd =
      Printf.sprintf
        "/usr/bin/clang-13 -Xclang -ast-dump -fno-color-diagnostics \
         -fsyntax-only -x c-header %s -nostdinc 2> /dev/null"
        header_path
    in
    let ic = Unix.open_process_in cmd in
    let rec process_line () =
      try
        let line = input_line ic in
        let line_lower = String.lowercase_ascii line in
        let contains_typedefdecl =
          Re.execp (Re.Pcre.regexp "typedefdecl") line_lower
        in
        (if contains_typedefdecl then
           (* Format: -TypedefDecl ... <col:1, col:36> col:36 TYPEDEF_NAME 'base_type':'base_type' *)
           let base_type_str =
             try
               let type_re = Re.Pcre.regexp "'([^']*?)'" in
               let groups = Re.exec type_re line in
               Re.Group.get groups 1 |> String.trim
             with Not_found -> failwith "no canonical type for typedef?"
           in
           try
             let name_re =
               Re.Pcre.regexp {|(\bimplicit\s+)?([_a-zA-Z][_a-zA-Z0-9]*)\s+'|}
             in
             let groups = Re.exec name_re line in
             match Re.Group.get_opt groups 1 with
             | Some _ -> ()
             | None ->
                 Hashtbl.replace typedef_table
                   (Re.Group.get groups 2 |> String.trim)
                   base_type_str
           with Not_found -> failwith "no name for typedef?");
        process_line ()
      with End_of_file -> ignore (Unix.close_process_in ic)
    in
    process_line ()

type fuzz_data_kind =
  | FUZZ_STRING
  | FUZZ_WSTRING
  | FUZZ_DATA
  | FUZZ_SIZE
  | FUZZ_COUNT
  | FUZZ_RET
  | FUZZ_P_DOUBLE

let get_fuzz_data_kind_str (data_kind : fuzz_data_kind) : string =
  match data_kind with
  | FUZZ_STRING -> "FUZZ_STRING"
  | FUZZ_WSTRING -> "FUZZ_WSTRING"
  | FUZZ_DATA -> "FUZZ_DATA"
  | FUZZ_SIZE -> "FUZZ_SIZE"
  | FUZZ_COUNT -> "FUZZ_COUNT"
  | FUZZ_RET -> "FUZZ_RET"
  | FUZZ_P_DOUBLE -> "FUZZ_P_DOUBLE"

let default_ptr_attr =
  {
    pa_direction = PtrNoDirection;
    pa_size = empty_ptr_size;
    pa_isptr = false;
    pa_isary = false;
    pa_isstr = false;
    pa_iswstr = false;
    pa_rdonly = false;
    pa_chkptr = true;
  }

(* ========== JSON to Struct Def Conversion ========== *)

(* Extract all array dimensions from type string like "[10 x [20 x i32]]" *)
let rec extract_array_dims (tystr : string) : int list =
  let tystr = String.trim tystr in
  (* Match pattern: [content] and extract the content *)
  let re = Str.regexp {|^\[\(.*\)\]$|} in
  if Str.string_match re tystr 0 then
    let content = Str.matched_group 1 tystr |> String.trim in
    (* Find 'x' position in the content *)
    let x_pos = String.index content 'x' in
    let dim_str = String.sub content 0 x_pos |> String.trim in
    let elem_tystr =
      String.sub content (x_pos + 1) (String.length content - x_pos - 1)
      |> String.trim
    in
    let dim = int_of_string dim_str in
    dim :: extract_array_dims elem_tystr
  else []

(* Convert type string to atype *)
let rec tystr_to_atype (tystr : string) : atype =
  (* Remove leading/trailing whitespace *)
  let tystr = String.trim tystr in
  if tystr = "{}*" then
    (* {}* seems a function pointer with one parameter is mistakenly recognized as a struct pointer *)
    Ptr Void
  else if String.ends_with ~suffix:"*" tystr then
    (* Check for pointer *)
    let base_tystr =
      String.sub tystr 0 (String.length tystr - 1) |> String.trim
    in
    Ptr (tystr_to_atype base_tystr)
  else if String.starts_with ~prefix:"[" tystr then
    (* Check for array [N x T] *)
    let re = Re.Pcre.regexp {|^\[.*? x (.*)\]$|} in
    (* Printf.printf "tystr: %s\n" tystr; *)
    let elem_tystr =
      match Re.exec_opt re tystr with
      | Some g -> Re.Group.get g 1 |> String.trim
      | None -> failwith "not a array?"
    in
    (* Printf.printf "elem_tystr: %s\n" elem_tystr; *)
    (* flush stdout; *)
    tystr_to_atype elem_tystr
  else if String.starts_with ~prefix:"%struct." tystr then
    let struct_name = String.sub tystr 8 (String.length tystr - 8) in
    Struct struct_name
  else if String.starts_with ~prefix:"%union." tystr then
    (* Check for union *)
    let union_name = String.sub tystr 7 (String.length tystr - 7) in
    Union union_name
  else (* Primitive types *)
    match tystr with
    | "void" -> Void
    | "i8" -> Int8
    | "i16" -> Int16
    | "i32" -> Int32
    | "i64" -> Int64
    | "float" -> Float
    | "double" -> Double
    | _ ->
        let re = Str.regexp {|^.* (.*)$|} in
        if Str.string_match re tystr 0 then
          (* function pointer *)
          Void
        else failwith "unknown type"

(* Convert JSON field info to pdecl *)
let json_field_to_pdecl (field_idx : string) (node : Yojson.Basic.t) :
    pdecl option =
  match node with
  | `Assoc field_attrs -> (
      let get_attr key =
        try
          match List.assoc key field_attrs with
          | `String s -> Some s
          | `Int i -> Some (string_of_int i)
          | `Bool b -> Some (string_of_bool b)
          | _ -> failwith "unsupported attribute value"
        with Not_found -> None
      in
      let type_str =
        match get_attr "Type" with
        | Some s -> s
        | None -> failwith "Type is required"
      in
      let kind_str =
        match get_attr "Kind" with
        | Some s -> s
        | None -> failwith "Kind is required"
      in
      let count =
        match get_attr "Count" with
        | Some s -> Some (int_of_string s)
        | None -> None
      in

      let aty = tystr_to_atype type_str in
      (* Extract all dimensions from type string (supports multi-dimensional arrays) *)
      let array_dims_from_type = extract_array_dims type_str in
      (* Use dimensions from type string if available, otherwise fall back to Count *)
      let array_dims =
        if array_dims_from_type <> [] then array_dims_from_type
        else match count with Some n -> [ n ] | None -> []
      in
      let declr = { identifier = "field_" ^ field_idx; array_dims } in
      match kind_str with
      | "Pointer" | "Array" -> Some (PTPtr (aty, default_ptr_attr), declr)
      | _ -> Some (PTVal aty, declr))
  | _ -> failwith "not a field?"

let json_field_to_mdecl (field_idx : string) (node : Yojson.Basic.t) :
    mdecl option =
  match node with
  | `Assoc field_attrs ->
      let get_attr key =
        try
          match List.assoc key field_attrs with
          | `String s -> Some s
          | `Int i -> Some (string_of_int i)
          | `Bool b -> Some (string_of_bool b)
          | _ -> failwith "unsupported attribute value"
        with Not_found -> None
      in
      let type_str =
        match get_attr "Type" with
        | Some s -> s
        | None -> failwith "Type is required"
      in
      let count =
        match get_attr "Count" with
        | Some s -> Some (int_of_string s)
        | None -> None
      in

      let aty = tystr_to_atype type_str in
      (* Extract all dimensions from type string (supports multi-dimensional arrays) *)
      let array_dims_from_type = extract_array_dims type_str in
      (* Use dimensions from type string if available, otherwise fall back to Count *)
      let array_dims =
        if array_dims_from_type <> [] then array_dims_from_type
        else match count with Some n -> [ n ] | None -> []
      in
      let declr = { identifier = "field_" ^ field_idx; array_dims } in
      Some (aty, declr)
  | _ -> failwith "not a field?"

(* Convert JSON struct definition to struct_def *)
let json_to_comp_def (comp_name : string) (node : Yojson.Basic.t) :
    composite_type option =
  let is_struct = ref false in
  let is_union = ref false in
  let cname =
    if String.starts_with ~prefix:"%struct." comp_name then (
      is_struct := true;
      String.sub comp_name 8 (String.length comp_name - 8))
    else if String.starts_with ~prefix:"%union." comp_name then (
      is_union := true;
      String.sub comp_name 7 (String.length comp_name - 7))
    else failwith "not start with %struct?"
  in
  match node with
  | `Assoc field_list ->
      (* Sort fields by index (field keys are "0", "1", "2", ...) *)
      let sorted_fields =
        List.sort
          (fun (k1, _) (k2, _) -> compare (int_of_string k1) (int_of_string k2))
          field_list
      in
      if !is_struct then
        let pdecls =
          List.fold_left
            (fun acc (field_idx, field_json) ->
              match json_field_to_pdecl field_idx field_json with
              | Some pdecl -> pdecl :: acc
              | None -> acc)
            [] sorted_fields
          |> List.rev
        in
        if pdecls = [] then None
        else Some (StructDef { sname = cname; smlist = pdecls })
      else if !is_union then
        let mdecls =
          List.fold_left
            (fun acc (field_idx, field_json) ->
              match json_field_to_mdecl field_idx field_json with
              | Some mdecl -> mdecl :: acc
              | None -> acc)
            [] sorted_fields
          |> List.rev
        in
        if mdecls = [] then None
        else Some (UnionDef { uname = cname; umlist = mdecls })
      else failwith "not struct or union?"
  | _ -> failwith "not a json node?"

(* ========== Code Generation Helpers ========== *)

let mk_fuzz_wrapper_name (fname : string) : string = "fuzz_" ^ fname
let mk_ocall_wrapper_name (fname : string) : string = "__ocall_wrapper_" ^ fname
let get_indent (n : int) : string = String.make n '\t'
(* ========== Parameter Content Generation ========== *)

(* Find parameter index by name *)
let find_param_idx (plist : pdecl list) (name : string) : int option =
  let rec find idx = function
    | [] -> None
    | (_, declr) :: rest ->
        if declr.identifier = name then Some idx else find (idx + 1) rest
  in
  find 0 plist

(* ========== Structure Definition Handling ========== *)

(* Global structure definitions from enclave_content *)
let comp_defs : (string, composite_type) Hashtbl.t = Hashtbl.create 32

(* Initialize composite definitions from enclave_content *)
let init_comp_defs (ec : enclave_content) : unit =
  Hashtbl.clear comp_defs;
  List.iter
    (fun comp ->
      match comp with
      | StructDef sd -> Hashtbl.replace comp_defs sd.sname comp
      | UnionDef ud -> Hashtbl.replace comp_defs ud.uname comp
      | EnumDef ed -> Hashtbl.replace comp_defs ed.enname comp)
    ec.comp_defs

(* Load typeinfo and populate struct_defs - call this after load_typeinfo *)
let get_comp_def (name : string) : composite_type option =
  try Some (Hashtbl.find comp_defs name)
  with Not_found -> (
    Hashtbl.find_opt typedef_table name |> function
    | Some actual_tystr -> (
        match ast_ty_to_atype actual_tystr with
        | Some (Struct sname) -> Hashtbl.find_opt comp_defs sname
        | Some (Union uname) -> Hashtbl.find_opt comp_defs uname
        | _ -> None)
    | None -> None)

let rec get_arr_suffix (dims : int list) : string =
  match dims with
  | [] -> ""
  | dim :: rest ->
      Printf.sprintf "[%s]%s" (string_of_int dim) (get_arr_suffix rest)

(* Get parameter type string *)
let get_param_str (pd : pdecl) : string =
  let pty, declr = pd in
  match pty with
  | PTVal ty ->
      Printf.sprintf "%s %s" (Ast.get_tystr ty) declr.identifier
      ^ get_arr_suffix declr.array_dims
  | PTPtr (ty, pa) ->
      Printf.sprintf "%s %s %s"
        (if pa.pa_rdonly then "const" else "")
        (Ast.get_tystr ty) declr.identifier
      ^ get_arr_suffix declr.array_dims

(* Check if a type contains pointer that needs recursive handling *)
let rec struct_def_has_pointer (sd : struct_def) : bool =
  List.exists
    (fun (pt, _) ->
      match pt with PTPtr _ -> true | PTVal t -> atype_has_pointer t)
    sd.smlist

and atype_has_pointer (ty : atype) : bool =
  match ty with
  | Ptr _ -> true
  | Struct s -> (
      match get_comp_def s with
      | Some cd -> (
          match cd with
          | StructDef sd -> struct_def_has_pointer sd
          | _ -> failwith "not a struct?")
      | None -> false)
  | Foreign f -> (
      match get_comp_def f with
      | Some cd -> (
          match cd with
          | StructDef sd ->
              Printf.eprintf "found struct_def of %s\n" (Ast.get_tystr ty);
              struct_def_has_pointer sd
          | _ -> false)
      | None ->
          (* can be a function pointer *)
          false
          (* failwith "foreign and not a struct" *))
  | _ -> false

let get_loop_var (global_depth : int) (loop_depth : int) : string =
  Printf.sprintf "i_%d_%d" global_depth loop_depth

let get_loop_var2 (global_depth : int) (suffix : string) : string =
  Printf.sprintf "i_%d_%s" global_depth suffix

let get_identity_with_arr_suffix (declr : declarator) : string =
  declr.identifier ^ get_arr_suffix declr.array_dims

let rec get_arr_subscript (dims : int list) (global_depth : int)
    (loop_depth : int) : string =
  match dims with
  | [] -> ""
  | _ :: rest ->
      Printf.sprintf "[%s]%s"
        (get_loop_var global_depth loop_depth)
        (get_arr_subscript rest global_depth (loop_depth + 1))

let decl_var (ok : bool) (tystr : string) (var_name : string) (indent_cnt : int)
    : string =
  if ok then Printf.sprintf "%s%s %s;\n" (get_indent indent_cnt) tystr var_name
  else ""

let decl_nullify_ptr (ok : bool) (tystr : string) (var_name : string)
    (indent_cnt : int) : string =
  if ok then
    Printf.sprintf "%s%s %s = NULL;\n" (get_indent indent_cnt) tystr var_name
  else ""

let gen_sizeof_str (ty_str : string) : string =
  if ty_str = "void" then "1" else Printf.sprintf "sizeof(%s)" ty_str

let gen_basic_data (ty : atype) (var_access : string) (feed_data : bool)
    (data_kind : fuzz_data_kind) (indent_cnt : int) : string =
  if feed_data then
    Printf.sprintf "%sDFGetBytes(&%s, %s, \"\", %s);\n" (get_indent indent_cnt)
      var_access
      (gen_sizeof_str (Ast.get_tystr ty))
      (get_fuzz_data_kind_str data_kind)
  else ""

let gen_ptr_data (var_access : string) (count_var : string) (elety : atype)
    (feed_data : bool) (data_kind : fuzz_data_kind) (indent_cnt : int) : string
    =
  if feed_data then
    Printf.sprintf "%sDFGetBytes((void *)%s, %s * %s, \"\", %s);\n"
      (get_indent indent_cnt) var_access count_var
      (gen_sizeof_str (Ast.get_tystr elety))
      (get_fuzz_data_kind_str data_kind)
  else ""

let gen_ptr_data2 (var_access : string) (count_var : string)
    (elem_tystr : string) (feed_data : bool) (indent_cnt : int) : string =
  if feed_data then
    Printf.sprintf "%sDFGetBytes((void *)%s, %s * %s, \"\", FUZZ_DATA);\n"
      (get_indent indent_cnt) var_access count_var
      (gen_sizeof_str elem_tystr)
  else ""

let get_count_var (depth : int) (who : string) : string =
  Printf.sprintf "count_%d_%s" depth who

let get_decl_stat (ok : bool) ((pty, declr) : pdecl) (indent_cnt : int) : string
    =
  match pty with
  | PTVal ty ->
      assert (declr.array_dims = [] || failwith "array is PTVal?");
      decl_var ok (Ast.get_tystr ty)
        (get_identity_with_arr_suffix declr)
        indent_cnt
  | PTPtr (ty, attr) -> (
      match ty with
      | Ptr _ ->
          assert (
            declr.array_dims = []
            || failwith "not support array pointer or pointer array");
          decl_nullify_ptr ok (Ast.get_tystr ty) declr.identifier indent_cnt
      | Foreign _ ->
          if attr.pa_isary then
            decl_var ok (Ast.get_tystr ty)
              (get_identity_with_arr_suffix declr)
              indent_cnt
          else if attr.pa_isptr then
            decl_nullify_ptr ok (Ast.get_tystr ty)
              (get_identity_with_arr_suffix declr)
              indent_cnt
          else failwith "foreign isn't isary/isptr?"
      | _ ->
          assert (
            declr.array_dims <> []
            || failwith "PTPtr of non-pointer type not an array?");
          decl_var ok (Ast.get_tystr ty)
            (get_identity_with_arr_suffix declr)
            indent_cnt)

let rec gen_struct_data_rec (sd : struct_def) (var_access : string)
    (feed_data : bool) (depth : int) (is_ecall : bool) : string =
  let sub_prepared = Hashtbl.create 16 in
  let member_codes =
    List.mapi
      (fun midx _ ->
        gen_param_rec sd.smlist midx sub_prepared (var_access ^ ".") (depth + 1)
          feed_data is_ecall FUZZ_DATA)
      sd.smlist
  in
  String.concat "" member_codes

(* Recursive parameter preparation *)
and gen_param_rec (plist : pdecl list) (param_idx : int)
    (prepared : (int, unit) Hashtbl.t) (prefix : string) (depth : int)
    (feed_data : bool) (is_ecall : bool) (data_kind : fuzz_data_kind) : string =
  if Hashtbl.mem prepared param_idx then ""
  else (
    Hashtbl.add prepared param_idx ();
    if depth > !Config.g_max_recursion_depth then ""
    else
      let pty, declr = List.nth plist param_idx in
      let var_decl_stat =
        if is_ecall then get_decl_stat (prefix = "") (pty, declr) (depth + 1)
        else ""
      in
      let var_access = prefix ^ declr.identifier in

      (* 处理数组维度：生成嵌套 for 循环 *)
      let rec wrap_array_loops (dims : int list) (var_access : string)
          (global_depth : int) (loop_depth : int) (inner_code : string) : string
          =
        match dims with
        | [] -> inner_code
        | dim :: rest ->
            let loop_var = get_loop_var global_depth loop_depth in
            let inner_var_access =
              Printf.sprintf "%s[%s]" var_access loop_var
            in
            let wrapped =
              wrap_array_loops rest inner_var_access global_depth
                (loop_depth + 1) inner_code
            in
            let indent = get_indent (global_depth + loop_depth + 1) in
            Printf.sprintf "%sfor (size_t %s = 0; %s < %d; %s++) {\n%s\n%s}\n"
              indent loop_var loop_var dim loop_var wrapped indent
      in
      (* 为了在内部遍历时使用，加上数组后缀 *)
      let inner_var_access =
        if declr.array_dims = [] then var_access
        else var_access ^ get_arr_subscript declr.array_dims depth 0
      in
      let arr_elem_code =
        match pty with
        | PTVal ty -> (
            match ty with
            | Ptr t -> failwith "PTVal of Ptr?"
            | Struct struct_ty_name -> (
                match get_comp_def struct_ty_name with
                | Some (StructDef sd) ->
                    if atype_has_pointer ty then
                      gen_struct_data_rec sd inner_var_access feed_data depth
                        is_ecall
                    else
                      gen_basic_data ty inner_var_access feed_data data_kind
                        (depth + 1)
                | Some _ -> failwith "not a struct?"
                | None ->
                    if String.starts_with ~prefix:"anon" struct_ty_name then
                      (* Anonymous struct, skip *)
                      ""
                    else failwith "no struct_def for non-anon Struct?")
            | Foreign foreign_ty_name -> (
                match get_comp_def foreign_ty_name with
                | Some (StructDef sd) ->
                    if atype_has_pointer ty then
                      gen_struct_data_rec sd inner_var_access feed_data depth
                        is_ecall
                    else
                      gen_basic_data ty inner_var_access feed_data data_kind
                        (depth + 1)
                | _ ->
                    gen_basic_data ty inner_var_access feed_data data_kind
                      (depth + 1))
            | _ ->
                gen_basic_data ty inner_var_access feed_data data_kind
                  (depth + 1))
        | PTPtr (ty, attr) -> (
            let prerequisites_code = Buffer.create 1024 in
            match ty with
            | Ptr elety ->
                if declr.array_dims <> [] then
                  failwith "not support array pointer or pointer array";
                if attr.pa_isstr then
                  Printf.sprintf
                    "%s%s = (char *)DFGetBytes(NULL, 0, \"\", FUZZ_STRING);\n"
                    (get_indent (depth + 1))
                    inner_var_access
                else if attr.pa_iswstr then
                  Printf.sprintf
                    "%s%s = (wchar_t *)DFGetBytes(NULL, 0, \"\", FUZZ_WSTRING);\n"
                    (get_indent (depth + 1))
                    inner_var_access
                else
                  let tystr = Ast.get_tystr ty in
                  let elem_tystr = Ast.get_tystr elety in
                  let count_var = get_count_var depth declr.identifier in
                  let count_stat =
                    if
                      attr.pa_direction = PtrNoDirection
                      && attr.pa_size = empty_ptr_size
                    then
                      Printf.sprintf
                        "%ssize_t %s = DFGetUserCheckCount(%s, \"\");\n"
                        (get_indent (depth + 1))
                        count_var
                        (gen_sizeof_str elem_tystr)
                    else
                      (* Check and prepare dependent count parameter first *)
                      let count_tag : string =
                        match attr.pa_size.ps_count with
                        | Some (ANumber n) -> string_of_int n
                        | Some (AString dep_name) ->
                            if is_ecall then
                              match find_param_idx plist dep_name with
                              | Some dep_idx ->
                                  Buffer.add_string prerequisites_code
                                    (gen_param_rec plist dep_idx prepared prefix
                                       depth true is_ecall FUZZ_COUNT);
                                  let _, dep_declr = List.nth plist dep_idx in
                                  assert (
                                    dep_declr.identifier = dep_name
                                    || failwith "depended count name mismatch");
                                  prefix ^ dep_name
                              | None -> failwith "not find count param?"
                            else prefix ^ dep_name
                        | None -> "1"
                      in
                      (* Check and prepare dependent size parameter first *)
                      let size_tag =
                        match attr.pa_size.ps_size with
                        | Some (ANumber n) -> string_of_int n
                        | Some (AString dep_name) ->
                            if is_ecall then
                              match find_param_idx plist dep_name with
                              | Some dep_idx ->
                                  Buffer.add_string prerequisites_code
                                    (gen_param_rec plist dep_idx prepared prefix
                                       depth true is_ecall FUZZ_SIZE);
                                  let _, dep_declr = List.nth plist dep_idx in
                                  assert (
                                    dep_declr.identifier = dep_name
                                    || failwith "depended size name mismatch");
                                  prefix ^ dep_name
                              | None -> failwith "not find size param?"
                            else prefix ^ dep_name
                        | None -> gen_sizeof_str elem_tystr
                      in
                      if is_ecall then
                        Printf.sprintf
                          "%ssize_t %s = ((%s) * (%s) + %s - 1 ) / %s;\n"
                          (get_indent (depth + 1))
                          count_var count_tag size_tag
                          (gen_sizeof_str elem_tystr)
                          (gen_sizeof_str elem_tystr)
                      else
                        Printf.sprintf "%ssize_t %s = ((%s) * (%s)) / %s;\n"
                          (get_indent (depth + 1))
                          count_var count_tag size_tag
                          (gen_sizeof_str elem_tystr)
                  in

                  let has_inner_ptr = atype_has_pointer elety in
                  let get_buf_stat =
                    if is_ecall then
                      Printf.sprintf "%s%s = (%s)DFManagedCalloc(%s, %s);\n"
                        (get_indent (depth + 1))
                        inner_var_access tystr count_var
                        (gen_sizeof_str elem_tystr)
                    else ""
                  in
                  let pre_code = Buffer.contents prerequisites_code in
                  assert (
                    (is_ecall || pre_code = "") || failwith "ocall has precode?");
                  if has_inner_ptr then
                    let sub_prepared = Hashtbl.create 16 in
                    let pointee_code =
                      gen_param_rec
                        [
                          ( (match elety with
                            | Ptr _ -> PTPtr (elety, default_ptr_attr)
                            | _ -> PTVal elety),
                            {
                              identifier =
                                Printf.sprintf "%s_%d_deref" declr.identifier
                                  depth;
                              array_dims = [];
                            } );
                        ]
                        0 sub_prepared "" (depth + 1) feed_data is_ecall
                        FUZZ_DATA
                    in
                    let loop_var = get_loop_var2 depth declr.identifier in
                    let indent = get_indent (depth + 1) in
                    let assign_stat =
                      Printf.sprintf "%s%s[%s] = %s;\n" indent inner_var_access
                        loop_var
                        (Printf.sprintf "%s_%d_deref" declr.identifier depth)
                    in
                    let get_stat =
                      Printf.sprintf "%s%s = %s[%s];\n" indent
                        (Printf.sprintf "%s_%d_deref" declr.identifier depth)
                        inner_var_access loop_var
                    in
                    Printf.sprintf
                      "%s%s%s%sfor (size_t %s = 0; %s < %s; %s++) {\n%s\n%s}\n"
                      pre_code count_stat get_buf_stat indent loop_var loop_var
                      count_var loop_var
                      (if is_ecall then pointee_code ^ assign_stat
                       else
                         get_decl_stat true
                           ( (match elety with
                             | Ptr _ -> PTPtr (elety, default_ptr_attr)
                             | _ -> PTVal elety),
                             {
                               identifier =
                                 Printf.sprintf "%s_%d_deref" declr.identifier
                                   depth;
                               array_dims = [];
                             } )
                           (depth + 1)
                         ^ get_stat ^ pointee_code)
                      indent
                  else
                    let get_byte_stat =
                      gen_ptr_data inner_var_access count_var elety feed_data
                        data_kind (depth + 1)
                    in
                    let content = count_stat ^ get_buf_stat ^ get_byte_stat in
                    let set_null_stat =
                      Printf.sprintf "%s%s = NULL;\n"
                        (get_indent (depth + 1))
                        inner_var_access
                    in
                    if is_ecall then
                      let indent = get_indent (depth + 1) in
                      Printf.sprintf
                        "%s%s%sif (!DFEnableSetNull(\"\")) {\n%s\n%s}\n"
                        pre_code set_null_stat indent content indent
                    else pre_code ^ content
            | Foreign foreign_ty_name ->
                if attr.pa_isstr || attr.pa_iswstr then
                  failwith "Foreign and a string?"
                else if attr.pa_isary then
                  gen_basic_data ty (inner_var_access ^ "[0]") feed_data
                    data_kind (depth + 1)
                else if attr.pa_isptr then (
                  let tystr = Ast.get_tystr ty in
                  let count_var = get_count_var depth declr.identifier in
                  let var_deref_access = "*" ^ inner_var_access in
                  let count_stat =
                    if
                      attr.pa_direction = PtrNoDirection
                      && attr.pa_size = empty_ptr_size
                    then
                      Printf.sprintf
                        "%ssize_t %s = DFGetUserCheckCount(%s, \"\");\n"
                        (get_indent (depth + 1))
                        count_var
                        (gen_sizeof_str var_deref_access)
                    else
                      (* Check and prepare dependent count parameter first *)
                      let count_tag : string =
                        match attr.pa_size.ps_count with
                        | Some (ANumber n) -> string_of_int n
                        | Some (AString dep_name) ->
                            if is_ecall then
                              match find_param_idx plist dep_name with
                              | Some dep_idx ->
                                  Buffer.add_string prerequisites_code
                                    (gen_param_rec plist dep_idx prepared prefix
                                       depth true is_ecall FUZZ_COUNT);
                                  let _, dep_declr = List.nth plist dep_idx in
                                  assert (
                                    dep_declr.identifier = dep_name
                                    || failwith "depended count name mismatch");
                                  prefix ^ dep_name
                              | None -> failwith "not find count param?"
                            else prefix ^ dep_name
                        | None -> "1"
                      in
                      (* Check and prepare dependent size parameter first *)
                      let size_tag =
                        match attr.pa_size.ps_size with
                        | Some (ANumber n) -> string_of_int n
                        | Some (AString dep_name) ->
                            if is_ecall then
                              match find_param_idx plist dep_name with
                              | Some dep_idx ->
                                  Buffer.add_string prerequisites_code
                                    (gen_param_rec plist dep_idx prepared prefix
                                       depth true is_ecall FUZZ_SIZE);
                                  let _, dep_declr = List.nth plist dep_idx in
                                  assert (
                                    dep_declr.identifier = dep_name
                                    || failwith "depended size name mismatch");
                                  prefix ^ dep_name
                              | None -> failwith "not find size param?"
                            else prefix ^ dep_name
                        | None -> gen_sizeof_str var_deref_access
                      in
                      if is_ecall then
                        Printf.sprintf
                          "%ssize_t %s = ((%s) * (%s) + %s - 1 ) / %s;\n"
                          (get_indent (depth + 1))
                          count_var count_tag size_tag
                          (gen_sizeof_str var_deref_access)
                          (gen_sizeof_str var_deref_access)
                      else
                        Printf.sprintf "%ssize_t %s = ((%s) * (%s)) / %s;\n"
                          (get_indent (depth + 1))
                          count_var count_tag size_tag
                          (gen_sizeof_str var_deref_access)
                  in

                  if get_comp_def foreign_ty_name <> None then
                    failwith "PTPtr of Foreign and a composite type?";
                  let get_buf_stat =
                    if is_ecall then
                      Printf.sprintf "%s%s = (%s)DFManagedCalloc(%s, %s);\n"
                        (get_indent (depth + 1))
                        inner_var_access tystr count_var
                        (gen_sizeof_str var_deref_access)
                    else ""
                  in
                  let get_bytes_stat =
                    gen_ptr_data2 inner_var_access count_var var_deref_access
                      feed_data (depth + 1)
                  in
                  let content = count_stat ^ get_buf_stat ^ get_bytes_stat in
                  let set_null_stat =
                    Printf.sprintf "%s%s = NULL;\n"
                      (get_indent (depth + 1))
                      inner_var_access
                  in

                  let pre_code = Buffer.contents prerequisites_code in
                  if (not is_ecall) && pre_code <> "" then
                    failwith "ocall has precode?";
                  if is_ecall then
                    let indent = get_indent (depth + 1) in
                    Printf.sprintf
                      "%s%s%sif (!DFEnableSetNull(\"\")) {\n%s\n%s}\n" pre_code
                      set_null_stat indent content indent
                  else pre_code ^ content)
                else failwith "foreign isn't isary/isptr?"
            | _ ->
                assert (
                  declr.array_dims <> []
                  || failwith "PTPtr of non-pointer type not an array?");
                (* Pointer array not allowed *)
                gen_basic_data ty inner_var_access feed_data data_kind
                  (depth + 1))
      in
      (* 如果是数组，用 for 循环包裹；否则直接返回 arr_elem_code *)
      let loop_code =
        if declr.array_dims = [] then arr_elem_code
        else if arr_elem_code <> "" then
          wrap_array_loops declr.array_dims var_access depth 0 arr_elem_code
        else ""
      in
      var_decl_stat ^ loop_code)

let whether_feed (is_ecall : bool) (pty : parameter_type) : bool =
  match pty with
  | PTPtr (ty, attr) ->
      if is_ecall then attr.pa_direction <> PtrOut
      else attr.pa_direction <> PtrIn
  | PTVal ty -> is_ecall

(* Generate all parameter preparation code with proper ordering *)
let gen_all_params_prepare (fd : func_decl) (is_ecall : bool) : string =
  let prepared = Hashtbl.create 16 in
  let param_code : string list =
    List.mapi
      (fun idx (pty, declr) ->
        if is_ecall then
          gen_param_rec fd.plist idx prepared "" 0
            (whether_feed is_ecall pty)
            true FUZZ_DATA
        else
          match pty with
          | PTPtr (ty, attr) when attr.pa_direction <> PtrIn ->
              assert (whether_feed is_ecall pty = true || failwith "not feed?");
              let inner_code =
                gen_param_rec fd.plist idx prepared "" 0 true false FUZZ_DATA
              in
              let indent = get_indent 1 in
              Printf.sprintf "%sif (DFEnableModifyOCallRet(\"\")) {\n%s\n%s}\n"
                indent inner_code indent
          | _ -> "")
      fd.plist
  in
  String.concat "" param_code

(* ========== ECall Fuzzing Wrapper Generation ========== *)

let gen_ecall_fuzz_wrapper (tf : trusted_func) : string =
  let fd = tf.tf_fdecl in
  let wrapper_name = mk_fuzz_wrapper_name fd.fname in

  (* Function signature: sgx_status_t fuzz_xxx(void) *)
  let func_open = Printf.sprintf "sgx_status_t %s(void) {\n" wrapper_name in

  (* Prepare all parameters with recursive dependency handling *)
  let param_code = gen_all_params_prepare fd true in

  (* Build parameter list for ECall invocation *)
  let param_names = List.map (fun (_, declr) -> declr.identifier) fd.plist in
  let param_list_str =
    if param_names = [] then "" else ", " ^ String.concat ", " param_names
  in

  (* Handle return value *)
  let ret_decl, ret_param =
    if fd.rtype = Void then ("", "")
    else
      let prepared = Hashtbl.create 16 in
      ( gen_param_rec
          [
            ( (match fd.rtype with
              | Ptr _ -> PTPtr (fd.rtype, default_ptr_attr)
              | _ -> PTVal fd.rtype),
              { identifier = "ret"; array_dims = [] } );
          ]
          0 prepared "" 0 false true FUZZ_RET,
        ", &ret" )
  in

  (* Call the real ECall *)
  let indent = get_indent 1 in
  let call_ecall =
    Printf.sprintf
      "%ssgx_status_t status = %s(__hidden_sgxfuzzer_harness_global_eid%s%s);\n"
      indent fd.fname ret_param param_list_str
  in

  let func_close = Printf.sprintf "%sreturn status;\n}\n" indent in

  let fuzz_ecall_code =
    func_open ^ ret_decl ^ param_code ^ call_ecall ^ func_close
  in
  fuzz_ecall_code

(* ========== OCall Wrapper Generation ========== *)

let gen_ocall_wrapper (uf : untrusted_func) : string =
  let fd = uf.uf_fdecl in
  let wrapper_name = mk_ocall_wrapper_name fd.fname in

  let ret_tystr = Ast.get_tystr fd.rtype in
  let param_strs = List.map get_param_str fd.plist in
  let param_decl =
    if param_strs = [] then "void" else String.concat ", " param_strs
  in

  let func_open =
    Printf.sprintf "%s %s(%s)\n{\n" ret_tystr wrapper_name param_decl
  in

  (* Call real OCall *)
  let param_names = List.map (fun (_, declr) -> declr.identifier) fd.plist in
  let call_params = String.concat ", " param_names in

  let call_stmt, ret_stmt =
    if fd.rtype = Void then
      (Printf.sprintf "%s%s(%s);\n" (get_indent 1) fd.fname call_params, "")
    else
      ( Printf.sprintf "%s%s ret = %s(%s);\n" (get_indent 1) ret_tystr fd.fname
          call_params,
        get_indent 1 ^ "return ret;\n" )
  in

  (* Modify [out] pointer parameters *)
  let modify_out_params = gen_all_params_prepare fd false in

  (* Modify return value if non-void *)
  let modify_ret =
    if fd.rtype = Void then ""
    else
      let prepared = Hashtbl.create 16 in
      let inner_code =
        gen_param_rec
          [
            ( (match fd.rtype with
              | Ptr elety -> PTPtr (fd.rtype, default_ptr_attr)
              | _ -> PTVal fd.rtype),
              { identifier = "ret"; array_dims = [] } );
          ]
          0 prepared "" 0 true false FUZZ_RET
      in
      let indent = get_indent 1 in
      Printf.sprintf "%sif (DFEnableModifyOCallRet(\"\")) {\n%s\n%s}\n" indent
        inner_code indent
  in

  let func_close = "}\n" in

  func_open ^ call_stmt ^ modify_out_params ^ modify_ret ^ ret_stmt ^ func_close

(* ========== Global Arrays Generation ========== *)

let gen_fuzz_globals (ec : enclave_content) : string =
  (* Filter out sgxsan_ecall_ prefix functions *)
  let fuzz_ecalls =
    List.filter
      (fun tf ->
        not
          (String.length tf.tf_fdecl.fname >= 12
          && String.sub tf.tf_fdecl.fname 0 12 = "sgxsan_ecall"))
      ec.tfunc_decls
  in

  let fuzz_count = List.length fuzz_ecalls in

  (* Global EID *)
  let _ = "sgx_enclave_id_t __hidden_sgxfuzzer_harness_global_eid;\n\n" in

  (* ECall count *)
  let count_decl = Printf.sprintf "int gFuzzECallNum = %d;\n\n" fuzz_count in

  (* Function pointer array *)
  let wrapper_names =
    List.map (fun tf -> mk_fuzz_wrapper_name tf.tf_fdecl.fname) fuzz_ecalls
  in
  let array_entries = String.concat ",\n\t" wrapper_names in
  let array_decl =
    Printf.sprintf "sgx_status_t (*gFuzzECallArray[])(void) = {\n\t%s\n};\n\n"
      array_entries
  in

  (* Name array *)
  let name_entries =
    List.map (fun name -> Printf.sprintf "\"%s\"" name) wrapper_names
  in
  let name_array =
    Printf.sprintf "const char* gFuzzECallNameArray[] = {\n\t%s\n};\n\n"
      (String.concat ",\n\t" name_entries)
  in

  count_decl ^ array_decl ^ name_array

(* Recursively load all *.sgxsan.typeinfo.json files from a directory *)
let rec load_typeinfo_from_dir_rec (dir : string) : unit =
  if Sys.file_exists dir && Sys.is_directory dir then
    let files = Sys.readdir dir in
    Array.iter
      (fun fname ->
        (* Skip . and .. to avoid infinite recursion *)
        if fname <> "." && fname <> ".." then
          let fullpath = Filename.concat dir fname in
          if Sys.is_directory fullpath then
            (* Recursively process subdirectories *)
            load_typeinfo_from_dir_rec fullpath
          else if Filename.check_suffix fname ".sgxsan.typeinfo.json" then
            (* Process typeinfo JSON files *)
            try
              let json = Yojson.Basic.from_file fullpath in
              match json with
              | `Assoc entries ->
                  List.iter
                    (fun (comp_name, fields_json) ->
                      match json_to_comp_def comp_name fields_json with
                      | Some comp_ty -> (
                          match comp_ty with
                          | StructDef sd ->
                              Hashtbl.replace comp_defs sd.sname comp_ty
                          | UnionDef ud ->
                              Hashtbl.replace comp_defs ud.uname comp_ty
                          | EnumDef _ -> failwith "enum in typeinfo?")
                      | None -> ())
                    entries
              | _ -> ()
            with _ -> ())
      files

(* ========== Main Generation Function ========== *)

let gen_fuzzing_code (ec : enclave_content) (dirs : string list) :
    string * string * string * string =
  List.iter
    (fun header ->
      let header_path = Util.get_header_path header in
      match header_path with
      | Some path -> update_typedef_info path
      | None -> ())
    ec.include_list;
  (* Initialize composite definitions for recursive handling *)
  init_comp_defs ec;

  (* Load all *.sgxsan.typeinfo.json files from a directory (recursively) *)
  List.iter load_typeinfo_from_dir_rec dirs;

  (* Header *)
  let header =
    "\n\
     /* ========== Generated Fuzzing Harness Code ========== */\n\n\
     enum FuzzDataTy {\n\
     FUZZ_STRING,\n\
     FUZZ_WSTRING,\n\
     FUZZ_DATA,\n\
     FUZZ_SIZE,\n\
     FUZZ_COUNT,\n\
     FUZZ_RET,\n\
     FUZZ_P_DOUBLE,\n\
     };\n\
     /* DF Runtime function declarations */\n\
     extern uint8_t* DFGetBytes(void* ptr, size_t byteArrLen, const char* \
     cStrAsParamID, enum FuzzDataTy dataType);\n\
     extern size_t DFGetUserCheckCount(size_t eleSize, const char \
     *cStrAsParamID);\n\
     extern void *DFManagedCalloc(size_t count, size_t size);\n\
     extern int DFEnableSetNull(const char *cStrAsParamID);\n\
     extern int DFEnableModifyOCallRet(const char *cParamID);\n\
     extern sgx_enclave_id_t __hidden_sgxfuzzer_harness_global_eid;\n\n"
  in

  (* Filter ECalls - exclude sgxsan_ecall_ prefix *)
  let fuzz_ecalls =
    List.filter
      (fun tf ->
        let fname = tf.tf_fdecl.fname in
        not (String.length fname >= 12 && String.sub fname 0 12 = "sgxsan_ecall"))
      ec.tfunc_decls
  in

  (* Generate ECall wrappers *)
  let ecall_wrappers =
    String.concat "\n" (List.map gen_ecall_fuzz_wrapper fuzz_ecalls)
  in

  (* Filter OCalls - exclude sgxsan_ocall_ prefix *)
  let fuzz_ocalls =
    List.filter
      (fun uf ->
        let fname = uf.uf_fdecl.fname in
        not (String.length fname >= 12 && String.sub fname 0 12 = "sgxsan_ocall"))
      ec.ufunc_decls
  in

  (* Generate OCall wrappers *)
  let ocall_wrappers =
    String.concat "\n" (List.map gen_ocall_wrapper fuzz_ocalls)
  in

  (* Generate global arrays *)
  let globals = gen_fuzz_globals ec in

  (header, ecall_wrappers, ocall_wrappers, globals)
