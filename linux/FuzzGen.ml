(*
 * FuzzGen.ml - Fuzzing wrapper code generation for SGX ECalls/OCalls
 * 
 * This module generates fuzzing harness code that:
 * - Creates fuzz_ecall_xxx wrapper functions
 * - Creates __ocall_wrapper_xxx functions
 * - Uses DF runtime functions to obtain fuzz input
 *)

open Ast

type fuzz_data_kind =
  | FUZZ_STRING
  | FUZZ_WSTRING
  | FUZZ_DATA
  | FUZZ_SIZE
  | FUZZ_COUNT
  | FUZZ_RET

let get_fuzz_data_kind_str (data_kind : fuzz_data_kind) : string =
  match data_kind with
  | FUZZ_STRING -> "FUZZ_STRING"
  | FUZZ_WSTRING -> "FUZZ_WSTRING"
  | FUZZ_DATA -> "FUZZ_DATA"
  | FUZZ_SIZE -> "FUZZ_SIZE"
  | FUZZ_COUNT -> "FUZZ_COUNT"
  | FUZZ_RET -> "FUZZ_RET"

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

let mk_fuzz_wrapper_name (fname : string) : string = "fuzz_" ^ fname
let mk_ocall_wrapper_name (fname : string) : string = "__ocall_wrapper_" ^ fname
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

let gen_sizeof_str (ty_str : string) : string =
  if ty_str = "void" then "1" else Printf.sprintf "sizeof(%s)" ty_str

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
      Printf.sprintf "%s=DFGetCount(%s);" var_access (gen_sizeof_str_from_ty ty)
    else if data_kind == FUZZ_SIZE then
      Printf.sprintf "%s=DFGetSize();" var_access
    else
      Printf.sprintf "DFGetBytes(&%s, %s, %s);\n" var_access
        (gen_sizeof_str_from_ty ty)
        (get_fuzz_data_kind_str data_kind)
  else ""

let gen_ptr_data (var_access : string) (count_var : string) (elety : atype)
    (feed_data : bool) (data_kind : fuzz_data_kind) : string =
  if feed_data then
    Printf.sprintf "DFGetBytes((void *)%s, %s * %s, %s);\n" var_access count_var
      (gen_sizeof_str_from_ty elety)
      (get_fuzz_data_kind_str data_kind)
  else ""

let gen_ptr_data2 (var_access : string) (count_var : string)
    (elem_tystr : string) (feed_data : bool) : string =
  if feed_data then
    Printf.sprintf "DFGetBytes((void *)%s, %s * %s, FUZZ_DATA);\n" var_access
      count_var
      (gen_sizeof_str elem_tystr)
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
            Printf.sprintf "for (size_t %s = 0; %s < %d; %s++) {\n%s\n}\n"
              loop_var loop_var dim loop_var wrapped
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
                    else gen_basic_data ty inner_var_access feed_data data_kind
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
                    "%s = (char *)DFGetBytes(NULL, 0, FUZZ_STRING);\n"
                    inner_var_access
                else if attr.pa_iswstr then
                  Printf.sprintf
                    "%s = (wchar_t *)DFGetBytes(NULL, 0, FUZZ_WSTRING);\n"
                    inner_var_access
                else
                  let tystr = Ast.get_tystr ty in
                  let count_var = get_count_var depth declr.identifier in
                  let count_stat =
                    if
                      attr.pa_direction = PtrNoDirection
                      && attr.pa_size = empty_ptr_size
                    then
                      Printf.sprintf "size_t %s=DFGetCount(%s);" count_var
                        (gen_sizeof_str_from_ty elety)
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
                      Printf.sprintf "%s = (%s)DFManagedCalloc(%s, %s);\n"
                        inner_var_access tystr count_var
                        (gen_sizeof_str_from_ty elety)
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
                      gen_ptr_data inner_var_access count_var elety feed_data
                        data_kind
                    in
                    let content = count_stat ^ get_buf_stat ^ get_byte_stat in
                    let set_null_stat =
                      Printf.sprintf "%s = NULL;\n" inner_var_access
                    in
                    if is_ecall then
                      Printf.sprintf "%s%sif (!DFSetNull()) {\n%s\n}\n" pre_code
                        set_null_stat content
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
                  let var_deref_access = "*" ^ inner_var_access in
                  let count_stat =
                    if
                      attr.pa_direction = PtrNoDirection
                      && attr.pa_size = empty_ptr_size
                    then
                      Printf.sprintf "size_t %s=DFGetCount(%s);" count_var
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
                          "size_t %s = ((%s) * (%s) + %s - 1 ) / %s;\n"
                          count_var count_tag size_tag
                          (gen_sizeof_str var_deref_access)
                          (gen_sizeof_str var_deref_access)
                      else
                        Printf.sprintf "size_t %s = ((%s) * (%s)) / %s;\n"
                          count_var count_tag size_tag
                          (gen_sizeof_str var_deref_access)
                  in

                  if get_comp_def foreign_ty_name <> None then
                    failwith "PTPtr of Foreign and a composite type?";
                  let get_buf_stat =
                    if is_ecall then
                      Printf.sprintf "%s = (%s)DFManagedCalloc(%s, %s);\n"
                        inner_var_access tystr count_var
                        (gen_sizeof_str var_deref_access)
                    else ""
                  in
                  let get_bytes_stat =
                    gen_ptr_data2 inner_var_access count_var var_deref_access
                      feed_data
                  in
                  let content = count_stat ^ get_buf_stat ^ get_bytes_stat in
                  let set_null_stat =
                    Printf.sprintf "%s = NULL;\n" inner_var_access
                  in

                  let pre_code = Buffer.contents prerequisites_code in
                  if (not is_ecall) && pre_code <> "" then
                    failwith "ocall has precode?";
                  if is_ecall then
                    Printf.sprintf "%s%sif (!DFSetNull()) {\n%s\n}\n" pre_code
                      set_null_stat content
                  else pre_code ^ content)
                else failwith "foreign isn't isary/isptr?"
            | _ ->
                assert (
                  declr.array_dims <> []
                  || failwith "PTPtr of non-pointer type not an array?");
                (* Pointer array not allowed *)
                gen_basic_data ty inner_var_access feed_data data_kind)
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
              Printf.sprintf "if (DFModifyOCallRet()) {\n%s\n}\n" inner_code
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
              { identifier = "_fuzz_ret"; array_dims = [] } );
          ]
          0 prepared "" 0 false true FUZZ_RET,
        ", &_fuzz_ret" )
  in

  (* Call the real ECall *)
  let call_ecall =
    Printf.sprintf
      "sgx_status_t status = %s(__hidden_sgxfuzzer_harness_global_eid%s%s);\n"
      fd.fname ret_param param_list_str
  in

  let func_close = Printf.sprintf "return status;\n}\n" in

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
          0 prepared "" 0 true false FUZZ_RET
      in
      Printf.sprintf "if (DFModifyOCallRet()) {\n%s\n}\n" inner_code
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

(* ========== Main Generation Function ========== *)

let gen_fuzzing_code (ec : enclave_content) : string * string * string * string
    =
  (* Initialize composite definitions for recursive handling *)
  init_comp_defs ec;

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
     };\n\
     /* DF Runtime function declarations */\n\
     extern uint8_t* DFGetBytes(void* ptr, size_t byteArrLen, enum FuzzDataTy \
     dataType);\n\
     extern size_t DFGetCount(size_t size);\n\
     extern size_t DFGetSize();\n\
     extern void *DFManagedCalloc(size_t count, size_t size);\n\
     extern int DFSetNull();\n\
     extern int DFModifyOCallRet();\n\
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
