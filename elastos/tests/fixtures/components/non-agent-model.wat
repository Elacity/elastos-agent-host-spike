;; A non-agent guest. It asks for elastos://model/offers and invokes offers_list
;; once. The Runtime admits it with no model-token ceiling entry.
(component
  (import "elastos:bus/types@1.0.0" (instance $types
    (type $bus-error (variant
      (case "denied" string)
      (case "not-found" string)
      (case "invalid" string)
      (case "unavailable" string)
      (case "timeout" string)
      (case "internal" string)))
    (export "bus-error" (type (eq $bus-error)))
    (type $capability-request (record
      (field "resource" string)
      (field "actions" (list string))
      (field "reason" string)))
    (export "capability-request" (type (eq $capability-request)))
    (type $capability-grant (record
      (field "id" string)
      (field "resource" string)
      (field "actions" (list string))
      (field "expires-at-ms" (option u64))))
    (export "capability-grant" (type (eq $capability-grant)))
    (type $invoke-request (record
      (field "resource" string)
      (field "operation" string)
      (field "body" (list u8))
      (field "grant" (option string))))
    (export "invoke-request" (type (eq $invoke-request)))
    (type $invoke-response (record
      (field "status" string)
      (field "body" (list u8))
      (field "audit" (option string))))
    (export "invoke-response" (type (eq $invoke-response)))))
  (alias export $types "bus-error" (type $bus-error))
  (alias export $types "capability-request" (type $capability-request))
  (alias export $types "capability-grant" (type $capability-grant))
  (alias export $types "invoke-request" (type $invoke-request))
  (alias export $types "invoke-response" (type $invoke-response))
  (import "elastos:bus/capabilities@1.0.0" (instance $capabilities
    (export "bus-error" (type (eq $bus-error)))
    (export "capability-request" (type (eq $capability-request)))
    (export "capability-grant" (type (eq $capability-grant)))
    (export "request" (func (param "request" $capability-request)
      (result (result $capability-grant (error $bus-error)))))))
  (import "elastos:bus/providers@1.0.0" (instance $providers
    (export "bus-error" (type (eq $bus-error)))
    (export "invoke-request" (type (eq $invoke-request)))
    (export "invoke-response" (type (eq $invoke-response)))
    (export "invoke" (func (param "request" $invoke-request)
      (result (result $invoke-response (error $bus-error)))))))
  (alias export $capabilities "request" (func $request-f))
  (alias export $providers "invoke" (func $invoke-f))
  (core module $guest
    (type $req (func (param i32 i32 i32 i32 i32 i32 i32)))
    (type $inv (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (table (export "table") 2 funcref)
    (memory (export "memory") 1)
    (global $heap (mut i32) (i32.const 4096))
    ;; 256: elastos://model/offers (22). 288: read (4). 296: offers_list (11).
    ;; 320: {} (2). 328: n9 (2). 352: one string (ptr 288, len 4).
    (data (i32.const 256) "elastos://model/offers")
    (data (i32.const 288) "read")
    (data (i32.const 296) "offers_list")
    (data (i32.const 320) "{}")
    (data (i32.const 328) "n9")
    (data (i32.const 352) "\20\01\00\00\04\00\00\00")
    (func $copy (param $dst i32) (param $src i32) (param $n i32)
      (local $i i32)
      (loop $more
        local.get $i
        local.get $n
        i32.ge_u
        if return end
        local.get $dst
        local.get $i
        i32.add
        local.get $src
        local.get $i
        i32.add
        i32.load8_u
        i32.store8
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $more))
    (func (export "realloc") (param $old i32) (param $old-len i32) (param $align i32) (param $new i32) (result i32)
      (local $ret i32)
      (local $mask i32)
      (local $n i32)
      local.get $align
      i32.const 1
      i32.lt_u
      if
        i32.const 1
        local.set $align
      end
      local.get $align
      i32.const 1
      i32.sub
      local.set $mask
      global.get $heap
      local.get $mask
      i32.add
      local.get $mask
      i32.const -1
      i32.xor
      i32.and
      local.set $ret
      local.get $old
      i32.const 0
      i32.ne
      if
        local.get $old-len
        local.get $new
        local.get $old-len
        local.get $new
        i32.gt_u
        select
        local.set $n
        local.get $ret
        local.get $old
        local.get $n
        call $copy
      end
      local.get $ret
      local.get $new
      i32.add
      global.set $heap
      local.get $ret)
    (func $request (param i32 i32 i32 i32 i32 i32 i32)
      local.get 0 local.get 1 local.get 2 local.get 3 local.get 4 local.get 5 local.get 6
      i32.const 0
      call_indirect (type $req))
    (func $invoke (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
      local.get 0 local.get 1 local.get 2 local.get 3 local.get 4
      local.get 5 local.get 6 local.get 7 local.get 8 local.get 9
      i32.const 1
      call_indirect (type $inv))
    (func (export "run") (result i32)
      ;; capability request. The grant record starts 8 bytes into the result.
      i32.const 256
      i32.const 22
      i32.const 352
      i32.const 1
      i32.const 328
      i32.const 2
      i32.const 512
      call $request
      i32.const 512
      i32.load8_u
      if unreachable end
      ;; invoke offers_list with that grant. option<string> some = 1.
      i32.const 256
      i32.const 22
      i32.const 296
      i32.const 11
      i32.const 320
      i32.const 2
      i32.const 1
      i32.const 520
      i32.load
      i32.const 524
      i32.load
      i32.const 768
      call $invoke
      i32.const 768
      i32.load8_u
      if unreachable end
      i32.const 0))
  (core instance $guest-i (instantiate $guest))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (alias core export $guest-i "table" (core table $table))
  (alias core export $guest-i "run" (core func $guest-run))
  (core func $request-l (canon lower (func $request-f)
    (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core func $invoke-l (canon lower (func $invoke-f)
    (memory $memory) (realloc $realloc) string-encoding=utf8))
  (core module $fix
    (type $req (func (param i32 i32 i32 i32 i32 i32 i32)))
    (type $inv (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (import "" "0" (func $request (type $req)))
    (import "" "1" (func $invoke (type $inv)))
    (import "" "$imports" (table 2 funcref))
    (elem (i32.const 0) func $request $invoke))
  (core instance $fix-args
    (export "0" (func $request-l))
    (export "1" (func $invoke-l))
    (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (func $run (result (result (error $bus-error)))
    (canon lift (core func $guest-run) (memory $memory)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))
