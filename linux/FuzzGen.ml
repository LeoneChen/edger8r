(*
 * FuzzGen.ml - Fuzzing wrapper code generation for SGX ECalls/OCalls
 * 
 * This module generates fuzzing harness code that:
 * - Creates fuzz_ecall_xxx wrapper functions
 * - Creates __ocall_wrapper_xxx functions
 * - Uses DF runtime functions to obtain fuzz input
 *)

open Ast

type fuzz_data_kind = FUZZ_DATA | FUZZ_SIZE | FUZZ_COUNT

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

(* ========== Code Generation Helpers ========== *)

let mk_fuzz_wrapper_name (fname : string) : string = "_harness_" ^ fname
let mk_ocall_wrapper_name (fname : string) : string = "_harness_" ^ fname

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
  Hashtbl.find_opt comp_defs name

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

let decl_var (ok : bool) (tystr : string) (var_name : string) : string =
  if ok then Printf.sprintf "%s %s;\n" tystr var_name else ""

let decl_nullify_ptr (ok : bool) (tystr : string) (var_name : string) : string =
  if ok then Printf.sprintf "%s %s = NULL;\n" tystr var_name else ""

let gen_safe_sizeof_ele_str (pt_tystr : string) : string =
  Printf.sprintf "safe_sizeof<typename std::remove_pointer<%s>::type>()"
    pt_tystr

let gen_sizeof_str_from_ty (ty : atype) : string =
  match ty with
  | Foreign _ -> "1"
  | _ ->
      let ty_str = Ast.get_tystr ty in
      if ty_str = "void" then "1" else Printf.sprintf "sizeof(%s)" ty_str

let gen_basic_data (ty : atype) (var_access : string) (feed_data : bool)
    (data_kind : fuzz_data_kind) : string =
  if feed_data then
    if data_kind == FUZZ_COUNT then
      let sizeof_str = gen_sizeof_str_from_ty ty in
      Printf.sprintf
        "%s = g_fdp->ConsumeIntegralInRange<size_t>(%s < 8 ? (20 / %s) : 1, \
         g_max_cnt);"
        var_access sizeof_str sizeof_str
    else if data_kind == FUZZ_SIZE then
      Printf.sprintf
        "%s = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);" var_access
    else
      Printf.sprintf "g_fdp->ConsumeData(&%s, %s);\n" var_access
        (gen_sizeof_str_from_ty ty)
  else ""

let gen_ptr_data (var_access : string) (count_var : string) (pt_ty : atype)
    (feed_data : bool) : string =
  if feed_data then
    Printf.sprintf "g_fdp->ConsumeData((void *)%s, %s * %s);\n" var_access
      count_var
      (match pt_ty with
      | Ptr elety -> gen_sizeof_str_from_ty elety
      | Foreign _ -> gen_safe_sizeof_ele_str (Ast.get_tystr pt_ty)
      | _ -> failwith "should be pointer type in gen_ptr_data?")
  else ""

let get_count_var (depth : int) (who : string) : string =
  Printf.sprintf "count_%d_%s" depth who

let get_decl_stat (ok : bool) ((pty, declr) : pdecl) : string =
  match pty with
  | PTVal ty ->
      assert (declr.array_dims = [] || failwith "array is PTVal?");
      decl_var ok (Ast.get_tystr ty) (get_identity_with_arr_suffix declr)
  | PTPtr (ty, attr) -> (
      match ty with
      | Ptr _ ->
          assert (
            declr.array_dims = []
            || failwith "not support array pointer or pointer array");
          decl_nullify_ptr ok (Ast.get_tystr ty) declr.identifier
      | Foreign _ ->
          if attr.pa_isary then
            decl_var ok (Ast.get_tystr ty) (get_identity_with_arr_suffix declr)
          else if attr.pa_isptr then
            decl_nullify_ptr ok (Ast.get_tystr ty)
              (get_identity_with_arr_suffix declr)
          else failwith "foreign isn't isary/isptr?"
      | _ ->
          assert (
            declr.array_dims <> []
            || failwith "PTPtr of non-pointer type not an array?");
          decl_var ok (Ast.get_tystr ty) (get_identity_with_arr_suffix declr))

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
    if depth > 5 then ""
    else
      let pty, declr = List.nth plist param_idx in
      let var_decl_stat =
        if is_ecall then get_decl_stat (prefix = "") (pty, declr) else ""
      in
      let var_access = prefix ^ declr.identifier in

      (* Handle array dimensions: generate nested for loops *)
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
            Printf.sprintf "for (size_t %s = 0; %s < %d; %s++) {\n%s\n}\n"
              loop_var loop_var dim loop_var wrapped
      in

      (* Add array subscript for inner iteration access *)
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
                    else gen_basic_data ty inner_var_access feed_data data_kind
                | Some _ -> failwith "not a struct?"
                | None -> failwith "no struct_def for Struct?")
            | Foreign foreign_ty_name -> (
                match get_comp_def foreign_ty_name with
                | Some (StructDef sd) ->
                    if atype_has_pointer ty then
                      gen_struct_data_rec sd inner_var_access feed_data depth
                        is_ecall
                    else gen_basic_data ty inner_var_access feed_data data_kind
                | _ -> gen_basic_data ty inner_var_access feed_data data_kind)
            | _ -> gen_basic_data ty inner_var_access feed_data data_kind)
        | PTPtr (ty, attr) -> (
            let prerequisites_code = Buffer.create 1024 in
            match ty with
            | Ptr elety ->
                if declr.array_dims <> [] then
                  failwith "not support array pointer or pointer array";
                if attr.pa_isstr then
                  Printf.sprintf
                    "size_t %s_strlen = \
                     g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen); \
                     %s = (char*)calloc(%s_strlen + 1, sizeof(char)); \
                     g_alloc_mgr.push_back((uint8_t*)%s); \
                     g_fdp->ConsumeData(%s, %s_strlen * sizeof(char));\n"
                    declr.identifier inner_var_access declr.identifier
                    inner_var_access inner_var_access declr.identifier
                else if attr.pa_iswstr then
                  Printf.sprintf
                    "size_t %s_strlen = \
                     g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen); \
                     %s = (wchar_t*)calloc(%s_strlen + 1, sizeof(wchar_t)); \
                     g_alloc_mgr.push_back((uint8_t*)%s); \
                     g_fdp->ConsumeData(%s, %s_strlen * sizeof(wchar_t));\n"
                    declr.identifier inner_var_access declr.identifier
                    inner_var_access inner_var_access declr.identifier
                else
                  let tystr = Ast.get_tystr ty in
                  let count_var = get_count_var depth declr.identifier in
                  let count_stat =
                    if
                      attr.pa_direction = PtrNoDirection
                      && attr.pa_size = empty_ptr_size
                    then
                      let sizof_str = gen_sizeof_str_from_ty elety in
                      Printf.sprintf
                        "size_t %s = g_fdp->ConsumeIntegralInRange<size_t>(%s \
                         < 8 ? (20 / %s) : 1, g_max_cnt);"
                        count_var sizof_str sizof_str
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
                        | None -> gen_sizeof_str_from_ty elety
                      in
                      if is_ecall then
                        Printf.sprintf
                          "size_t %s = ((%s) * (%s) + %s - 1 ) / %s;\n"
                          count_var count_tag size_tag
                          (gen_sizeof_str_from_ty elety)
                          (gen_sizeof_str_from_ty elety)
                      else
                        Printf.sprintf "size_t %s = ((%s) * (%s)) / %s;\n"
                          count_var count_tag size_tag
                          (gen_sizeof_str_from_ty elety)
                  in

                  let has_inner_ptr = atype_has_pointer elety in
                  let get_buf_stat =
                    if is_ecall then
                      Printf.sprintf
                        "%s = (%s)calloc(%s, %s); \
                         g_alloc_mgr.push_back((uint8_t*)%s);\n"
                        inner_var_access tystr count_var
                        (gen_sizeof_str_from_ty elety)
                        inner_var_access
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
                    let assign_stat =
                      Printf.sprintf "%s[%s] = %s;\n" inner_var_access loop_var
                        (Printf.sprintf "%s_%d_deref" declr.identifier depth)
                    in
                    let get_stat =
                      Printf.sprintf "%s = %s[%s];\n"
                        (Printf.sprintf "%s_%d_deref" declr.identifier depth)
                        inner_var_access loop_var
                    in
                    Printf.sprintf
                      "%s%s%sfor (size_t %s = 0; %s < %s; %s++) {\n%s\n}\n"
                      pre_code count_stat get_buf_stat loop_var loop_var
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
                         ^ get_stat ^ pointee_code)
                  else
                    let get_byte_stat =
                      gen_ptr_data inner_var_access count_var ty feed_data
                    in
                    let content = count_stat ^ get_buf_stat ^ get_byte_stat in
                    let set_null_stat =
                      Printf.sprintf "%s = NULL;\n" inner_var_access
                    in
                    if is_ecall then
                      Printf.sprintf
                        "%s%sif (g_fdp->ConsumeProbability<double>() < 0.9/* \
                         as an example */) { %s }"
                        pre_code set_null_stat content
                    else pre_code ^ content
            | Foreign foreign_ty_name ->
                if attr.pa_isstr || attr.pa_iswstr then
                  failwith "Foreign and a string?"
                else if attr.pa_isary then
                  gen_basic_data ty (inner_var_access ^ "[0]") feed_data
                    data_kind
                else if attr.pa_isptr then (
                  let tystr = Ast.get_tystr ty in
                  let count_var = get_count_var depth declr.identifier in
                  let count_stat =
                    if
                      attr.pa_direction = PtrNoDirection
                      && attr.pa_size = empty_ptr_size
                    then
                      let sizeof_str = gen_safe_sizeof_ele_str tystr in
                      Printf.sprintf
                        "size_t %s = g_fdp->ConsumeIntegralInRange<size_t>(%s \
                         < 8 ? (20 / %s) : 1, g_max_cnt);"
                        count_var sizeof_str sizeof_str
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
                        | None -> gen_safe_sizeof_ele_str tystr
                      in
                      if is_ecall then
                        Printf.sprintf
                          "size_t %s = ((%s) * (%s) + %s - 1 ) / %s;\n"
                          count_var count_tag size_tag
                          (gen_safe_sizeof_ele_str tystr)
                          (gen_safe_sizeof_ele_str tystr)
                      else
                        Printf.sprintf "size_t %s = ((%s) * (%s)) / %s;\n"
                          count_var count_tag size_tag
                          (gen_safe_sizeof_ele_str tystr)
                  in

                  if get_comp_def foreign_ty_name <> None then
                    failwith "PTPtr of Foreign and a composite type?";
                  let get_buf_stat =
                    if is_ecall then
                      Printf.sprintf
                        "%s = (%s)calloc(%s, %s); \
                         g_alloc_mgr.push_back((uint8_t*)%s);\n"
                        inner_var_access tystr count_var
                        (gen_safe_sizeof_ele_str tystr)
                        inner_var_access
                    else ""
                  in
                  let get_bytes_stat =
                    gen_ptr_data inner_var_access count_var ty feed_data
                  in
                  let content = count_stat ^ get_buf_stat ^ get_bytes_stat in
                  let set_null_stat =
                    Printf.sprintf "%s = NULL;\n" inner_var_access
                  in

                  let pre_code = Buffer.contents prerequisites_code in
                  if (not is_ecall) && pre_code <> "" then
                    failwith "ocall has precode?";
                  if is_ecall then
                    Printf.sprintf
                      "%s%sif (g_fdp->ConsumeProbability<double>() < 0.9/* as \
                       an example */) { %s }"
                      pre_code set_null_stat content
                  else pre_code ^ content)
                else failwith "foreign isn't isary/isptr?"
            | _ ->
                assert (
                  declr.array_dims <> []
                  || failwith "PTPtr of non-pointer type not an array?");
                (* Pointer array not allowed *)
                gen_basic_data ty inner_var_access feed_data data_kind)
      in

      (* Wrap with for loops if array, otherwise return directly *)
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
              Printf.sprintf
                "if (g_fdp->ConsumeProbability<double>() < 0.5/* as an example \
                 */) { %s }"
                inner_code
          | _ -> "")
      fd.plist
  in
  String.concat "" param_code

(* ========== ECall Fuzzing Wrapper Generation ========== *)

let gen_ecall_fuzz_wrapper (tf : trusted_func) : string =
  let fd = tf.tf_fdecl in
  let wrapper_name = mk_fuzz_wrapper_name fd.fname in

  (* Function signature: static void _harness_xxx(void) *)
  let func_open = Printf.sprintf "static void %s(void) {\n" wrapper_name in

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
              { identifier = "_fuzz_ret"; array_dims = [] } );
          ]
          0 prepared "" 0 false true FUZZ_DATA,
        ", &_fuzz_ret" )
  in

  (* Call the real ECall *)
  let call_ecall =
    Printf.sprintf "%s(__g_harness_eid%s%s);\n" fd.fname ret_param
      param_list_str
  in

  let func_close = "}" in

  func_open ^ ret_decl ^ param_code ^ call_ecall ^ func_close

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
    Printf.sprintf "extern \"C\" %s %s(%s)\n{\n" ret_tystr wrapper_name
      param_decl
  in

  (* Call real OCall *)
  let param_names = List.map (fun (_, declr) -> declr.identifier) fd.plist in
  let call_params = String.concat ", " param_names in

  let call_stmt, ret_stmt =
    if fd.rtype = Void then (Printf.sprintf "%s(%s);\n" fd.fname call_params, "")
    else
      ( Printf.sprintf "%s _fuzz_ret = %s(%s);\n" ret_tystr fd.fname call_params,
        "return _fuzz_ret;\n" )
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
              { identifier = "_fuzz_ret"; array_dims = [] } );
          ]
          0 prepared "" 0 true false FUZZ_DATA
      in
      Printf.sprintf
        "if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) { \
         %s }"
        inner_code
  in

  let func_close = "}\n" in

  func_open ^ call_stmt ^ modify_out_params ^ modify_ret ^ ret_stmt ^ func_close

(* ========== Main Generation Function ========== *)

let is_sgxsan_ecall (fname : string) : bool =
  String.length fname >= 12 && String.sub fname 0 12 = "sgxsan_ecall"

let is_sgxsan_ocall (fname : string) : bool =
  String.length fname >= 12 && String.sub fname 0 12 = "sgxsan_ocall"

let gen_fuzzing_code (ec : enclave_content) =
  (* Initialize composite definitions for recursive handling *)
  init_comp_defs ec;

  (* Generate harness.cpp file name *)
  let harness_fname = "harness.cpp" in

  (* Header with comprehensive documentation *)
  let header =
    Printf.sprintf
      "/*\n\
      \ * EnclaveFuzz - SGX Enclave Fuzzing Test Harness (Auto-Generated)\n\
      \ *\n\
      \ * Generated from EDL: %s.edl\n\
      \ *\n\
      \ * \
       ============================================================================\n\
      \ * Fuzzing Framework Architecture\n\
      \ * \
       ============================================================================\n\
      \ *\n\
      \ * Initialization (once):\n\
      \ *     LibFuzzer → LLVMFuzzerInitialize()\n\
      \ *                  ↓\n\
      \ *                 customized_init()  ← Register harnesses, calculate \
       weights\n\
      \ *\n\
      \ * Fuzzing loop (per input):\n\
      \ *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)\n\
      \ *                  ↓ Reinitialize g_fdp with new input\n\
      \ *                  ↓ Recreate enclave (__g_harness_eid)\n\
      \ *                  ↓\n\
      \ *                 customized_harness()  ← Weighted selection\n\
      \ *                  ↓\n\
      \ *                 _harness_xxx()   ← Auto-generated test functions\n\
      \ *                  ↓\n\
      \ *                 ECall → Enclave Code\n\
      \ *\n\
      \ * \
       ============================================================================\n\
      \ * EDL Attribute Reference\n\
      \ * \
       ============================================================================\n\
      \ *\n\
      \ * | Attribute    | Meaning             | Fuzzing Strategy \
       (ECall)         |\n\
      \ * \
       |--------------|---------------------|----------------------------------|\n\
      \ * | [in]         | Input to callee     | Generate fuzzy data \
       (Host→Encl)  |\n\
      \ * | [out]        | Output from callee  | Allocate buffer \
       (Encl→Host)      |\n\
      \ * | [in,out]     | Bidirectional       | Generate input + \
       allocate        |\n\
      \ * | [size=N]     | Buffer size (bytes) | Use N for \
       allocation             |\n\
      \ * | [count=N]    | Array element count | Use N * \
       sizeof(element)          |\n\
      \ * | [string]     | Null-terminated str | Ensure null \
       terminator           |\n\
      \ * | [user_check] | No auto checking    | High fuzz \
       value                  |\n\
      \ *\n\
      \ * CRITICAL: Direction Semantics ([in]/[out] relative to callee)\n\
      \ * - For ECalls (Enclave is callee):\n\
      \ *   [in] = Host→Enclave → FUZZ THIS in harness\n\
      \ *   [out] = Enclave→Host → Allocate buffer only\n\
      \ * - For OCalls (Host is callee):\n\
      \ *   [in] = Enclave→Host → No fuzzing needed\n\
      \ *   [out] = Host→Enclave → FUZZ THIS in OCall wrapper\n\
      \ *\n\
      \ * \
       ============================================================================\n\
      \ * Memory Management (Two Approaches)\n\
      \ * \
       ============================================================================\n\
      \ * Approach 1 (Auto-Managed by g_alloc_mgr) - CURRENT DEFAULT:\n\
      \ * - Use calloc() + g_alloc_mgr.push_back() to track allocations\n\
      \ * - Framework in LLVMFuzzerTestOneInput (at test.cpp) automatically \
       frees all tracked memory after each iteration\n\
      \ * - No explicit free() needed in harness functions\n\
      \ * - Pros: Simple, no memory leaks, centralized cleanup\n\
      \ * - Cons: Memory accumulates until end of iteration\n\
      \ *\n\
      \ * Approach 2 (Explicit free()):\n\
      \ * - Use calloc() without g_alloc_mgr tracking\n\
      \ * - Manually write free() calls at appropriate locations in harness code\n\
      \ * - Pros: Immediate memory release, lower memory footprint\n\
      \ * - Cons: Must ensure all allocations are freed, risk of memory leaks\n\
      \ *\n\
      \ * Usage: Choose approach based on your needs:\n\
      \ * - Default: g_alloc_mgr for safety and simplicity\n\
      \ * - Manual: Direct free() for memory-sensitive scenarios\n\
      \ *\n\
      \ * \
       ============================================================================\n\
      \ * Weighted Selection System\n\
      \ * \
       ============================================================================\n\
      \ * Each harness has a weight (default: 10). Adjust weights in \
       customized_init():\n\
      \ * - High weight (e.g., 50-100) for critical/bottleneck paths\n\
      \ * - Low weight (e.g., 1-5) for well-covered paths\n\
      \ * - Modify test_harness_registry[i].weight before calculating \
       total_weight\n\
      \ *\n\
      \ * \
       ============================================================================\n\
      \ */\n\n\
       #include \"%s_u.h\"\n\
       #include <errno.h>\n\
       #include <sgx_urts.h>\n\
       #include <stdint.h>\n\
       #include <stdio.h>\n\
       #include <stdlib.h>\n\
       #include <string.h>\n\
       #include \"FuzzedDataProvider.h\"\n\
       #include <vector>\n\n\
       template<typename T>\n\
       constexpr size_t safe_sizeof() {\n\
       return sizeof(typename std::conditional<std::is_void<T>::value, char, \
       T>::type);\n\
       }\n\n\
       // \
       ============================================================================\n\
       // Global Variables\n\
       // \
       ============================================================================\n\n\
       extern FuzzedDataProvider *g_fdp;\n\
       extern std::vector<uint8_t *> g_alloc_mgr;\n\
       extern sgx_enclave_id_t __g_harness_eid;\n\n\
       // Fuzzing configuration parameters\n\
       static size_t g_max_strlen = 128;  // Max string length for [string] \
       attributes\n\
       static size_t g_max_cnt = 32;      // Max count for unbounded arrays\n\
       static size_t g_max_size = 512;    // Max size for unbounded buffers\n\n\
       // \
       ============================================================================\n\
       // Test Harness Registration System\n\
       // \
       ============================================================================\n\n\
       typedef void (*TestHarness)(void);\n\n\
       struct TestHarnessEntry {\n\
      \    TestHarness function;\n\
      \    int weight;  // Selection weight (default: 10)\n\
       };\n\n\
       static TestHarnessEntry test_harness_registry[10240];\n\
       static unsigned int test_harness_count = 0;\n\
       static int total_weight = 0;\n\n"
      ec.file_shortnm ec.file_shortnm
  in

  (* Filter ECalls - exclude sgxsan_ecall_* prefix *)
  let fuzz_ecalls =
    List.filter
      (fun tf -> not (is_sgxsan_ecall tf.tf_fdecl.fname))
      ec.tfunc_decls
  in

  (* Generate ECall wrappers *)
  let ecall_wrappers =
    String.concat "\n" (List.map gen_ecall_fuzz_wrapper fuzz_ecalls)
  in

  (* Filter OCalls - exclude sgxsan_ocall_* prefix *)
  let fuzz_ocalls =
    List.filter
      (fun uf -> not (is_sgxsan_ocall uf.uf_fdecl.fname))
      ec.ufunc_decls
  in

  (* Generate OCall wrappers *)
  let ocall_wrappers =
    String.concat "\n" (List.map gen_ocall_wrapper fuzz_ocalls)
  in

  (* Generate init_weights function *)
  let init_weights_func =
    "// \
     ============================================================================\n\
     // Customized Initialization\n\
     // \
     ============================================================================\n\
     // This function is called once during fuzzer initialization\n\
     // (LLVMFuzzerInitialize).\n\
     //\n\
     // REQUIRED: Register all test harnesses by filling test_harness_registry[]\n\
     //\n\
     // Usage:\n\
     //   test_harness_registry[test_harness_count++] = {harness_function, \
     weight};\n\
     //\n\
     // IMPORTANT:\n\
     // - This function is called BEFORE any fuzzing iterations start\n\
     // - DO NOT create or initialize the enclave here (__g_harness_eid will \
     be 0)\n\
     // - DO NOT access g_fdp here (it's not initialized yet)\n\
     // - Keep initialization lightweight and fast\n\
     // - Weight MUST be > 0 for all harnesses\n\
     //\n\
     // Optional: Add custom initialization such as:\n\
     // - Environment variable configuration (setenv, putenv)\n\
     // - Global state initialization\n\
     // - Logging/debugging setup\n\
     // - Resource pre-allocation\n\
     // - Configuration file loading\n\
     // \
     ============================================================================\n\n\
     extern \"C\" void customized_init()\n\
     {\n\
    \    // \
     ========================================================================\n\
    \    // Step 1: Register all test harnesses\n\
    \    // \
     ========================================================================\n"
    ^ String.concat "\n"
        (List.map
           (fun tf ->
             let fname = tf.tf_fdecl.fname in
             let wrapper_name = mk_fuzz_wrapper_name fname in
             Printf.sprintf
               "    test_harness_registry[test_harness_count++] = {%s, 10};  \
                // Test %s"
               wrapper_name fname)
           fuzz_ecalls)
    ^ "\n\n\
      \    // \
       ========================================================================\n\
      \    // Step 2: Calculate total weight for weighted random selection\n\
      \    // \
       ========================================================================\n\n\
      \    // Sanity check: ensure at least one harness is registered\n\
      \    if (test_harness_count == 0) {\n\
      \        fprintf(stderr, \"[!] Error: No test harnesses registered\\n\");\n\
      \        abort();\n\
      \    }\n\n\
      \    total_weight = 0;\n\
      \    for (unsigned int i = 0; i < test_harness_count; i++) {\n\
      \        total_weight += test_harness_registry[i].weight;\n\
      \    }\n\n\
      \    // Sanity check: ensure total weight > 0\n\
      \    if (total_weight == 0) {\n\
      \        fprintf(stderr, \"[!] Error: All harness weights are 0\\n\");\n\
      \        abort();\n\
      \    }\n\n\
      \    // \
       ========================================================================\n\
      \    // Step 3: Custom initialization (optional)\n\
      \    // \
       ========================================================================\n\
      \    // Examples:\n\
      \    // - setenv(\"SGX_AESM_ADDR\", \"1\", 1);\n\
      \    // - freopen(\"/tmp/fuzzer.log\", \"w\", stderr);\n\
      \    // - Initialize global variables\n\
      \    // - Pre-load configuration files\n\
       }\n\n"
  in

  (* Generate customized_harness function *)
  let customized_harness_func =
    "// \
     ============================================================================\n\
     // Main Test Entry Point\n\
     // \
     ============================================================================\n\
     // Called by LLVMFuzzerTestOneInput for each fuzzing iteration\n\
     // Performs weighted random selection of test harnesses\n\
     // \
     ============================================================================\n\n\
     extern \"C\" void customized_harness(void)\n\
     {\n\
    \    // Weighted random selection\n\
    \    do {\n\
    \        int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight \
     - 1);\n\
    \        int cumulative = 0;\n\
    \        for (unsigned int i = 0; i < test_harness_count; i++) {\n\
    \            cumulative += test_harness_registry[i].weight;\n\
    \            if (rand_val < cumulative) {\n\
    \                test_harness_registry[i].function();\n\
    \                break;\n\
    \            }\n\
    \        }\n\
    \    } while (g_fdp->remaining_bytes() > 0);\n\
     }\n"
  in

  (* Write to harness.cpp file *)
  let out_chan = open_out harness_fname in
  output_string out_chan header;
  output_string out_chan
    "// \
     ============================================================================\n\
     // OCall Wrappers\n\
     // \
     ============================================================================\n\
     // These wrappers intercept OCalls and fuzz [out] parameters\n\
     // to test Enclave's resilience to untrusted data\n\
     // \
     ============================================================================\n\n";
  output_string out_chan ocall_wrappers;
  output_string out_chan "\n\n";
  output_string out_chan
    "// \
     ============================================================================\n\
     // ECall Test Harnesses\n\
     // \
     ============================================================================\n\
     // Auto-generated harness functions for each ECall\n\
     // Each function prepares fuzz inputs and invokes the corresponding ECall\n\
     // \
     ============================================================================\n\n";
  output_string out_chan ecall_wrappers;
  output_string out_chan "\n\n";
  output_string out_chan init_weights_func;
  output_string out_chan customized_harness_func;
  output_string out_chan "\n";
  close_out out_chan
