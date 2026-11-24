;; One guest asks, reads with the granted token, presents that grant, waits
;; for grant-revoked, and returns only when the next present is denied.
(component
  (import "elastos:bus/types@2.0.0" (instance $types
    (type $request (record (field "resource" string) (field "operation" string)
      (field "grant" (option string)) (field "params" (list u8))))
    (export "invoke-request" (type (eq $request)))
    (type $status (record (field "status" string) (field "audit" (option string))))
    (export "invoke-status" (type (eq $status)))
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "conflict" string)
      (case "internal" string)))
    (export "bus-error" (type (eq $error)))
    (type $grant (record (field "id" string) (field "resource" string)
      (field "actions" (list string)) (field "expires-at-ms" (option u64))))
    (export "grant" (type (eq $grant)))
    (type $grant-id string)
    (export "grant-id" (type (eq $grant-id)))
    (type $event (variant (case "stop-requested") (case "user-input" (list u8))
      (case "message" (list u8)) (case "grant-revoked" $grant-id)
      (case "opened") (case "closed")))
    (export "event" (type (eq $event)))))
  (alias export $types "invoke-request" (type $request))
  (alias export $types "invoke-status" (type $status))
  (alias export $types "bus-error" (type $error))
  (alias export $types "grant" (type $grant))
  (alias export $types "event" (type $event))
  (type $body (stream u8))
  (type $unit-result (result (error $error)))
  (type $trailer (future $unit-result))
  (type $invoke-result (result (tuple $status $body $trailer) (error $error)))
  (type $invoke (func async (param "request" $request) (param "body" (option $body)) (result $invoke-result)))
  (import "elastos:bus/providers@2.0.0" (instance $providers
    (export "invoke-request" (type (eq $request)))
    (export "invoke-status" (type (eq $status)))
    (export "bus-error" (type (eq $error)))
    (export "invoke" (func (type $invoke)))))
  (alias export $providers "invoke" (func $invoke-f))
  (type $request-result (result $grant (error $error)))
  (type $cap-request (func async (param "resource" string) (param "actions" (list string))
    (param "reason" string) (result $request-result)))
  (import "elastos:bus/capabilities@2.0.0" (instance $caps
    (export "grant" (type (eq $grant)))
    (export "bus-error" (type (eq $error)))
    (export "request" (func (type $cap-request)))))
  (alias export $caps "request" (func $request-f))
  ;; Type exports take the next index. Later types name that index, which is
  ;; the exported type, so a variant may contain another variant.
  (import "elastos:bus/ui@2.0.0" (instance $ui
    (type (variant
      (case "plain" string) (case "strong" string)
      (case "emphasis" string) (case "code" string)))
    (export "span" (type (eq 0)))
    (type (list 1))
    (type (tuple u8 2))
    (type (list 2))
    (type (tuple bool 4))
    (type (record (field "grant" string) (field "alt" string)))
    (export "image" (type (eq 6)))
    (type (variant
      (case "heading" 3) (case "paragraph" 2) (case "code-block" string)
      (case "quote" 4) (case "list" 5) (case "rule") (case "image" 7)))
    (export "nested" (type (eq 8)))
    (type (list 9))
    (type (variant (case "spans" 2) (case "blocks" 10)))
    (export "item" (type (eq 11)))
    (type (list 12))
    (type (tuple bool 13))
    (type (variant
      (case "heading" 3) (case "paragraph" 2) (case "code-block" string)
      (case "quote" 4) (case "list" 14) (case "rule") (case "image" 7)))
    (export "block" (type (eq 15)))
    (type (list 16))
    (export "bus-error" (type (eq $error)))
    (type (result (error 19)))
    (type (func async (param "document" 17) (result 20)))
    (export "present" (func (type 21)))))
  (alias export $ui "present" (func $present-f))
  (type $events (stream $event))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" $events) (result $reply)))
  (core module $shim
    (type $call (func (param i32 i32) (result i32)))
    (type $read (func (param i32 i32 i32) (result i32)))
    (type $drop (func (param i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (type $new-set (func (result i32)))
    (type $join (func (param i32 i32)))
    (type $request-call (func (param i32 i32) (result i32)))
    (type $present-call (func (param i32 i32 i32) (result i32)))
    (table (export "table") 10 funcref)
    (func (export "invoke") (type $call)
      local.get 0 local.get 1 i32.const 0 call_indirect (type $call))
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 1 call_indirect (type $read))
    (func (export "future") (type $call)
      local.get 0 local.get 1 i32.const 2 call_indirect (type $call))
    (func (export "drop") (type $drop)
      local.get 0 i32.const 3 call_indirect (type $drop))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 4 call_indirect (type $done))
    (func (export "new-set") (type $new-set)
      i32.const 5 call_indirect (type $new-set))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 6 call_indirect (type $join))
    (func (export "request") (type $request-call)
      local.get 0 local.get 1 i32.const 7 call_indirect (type $request-call))
    (func (export "present") (type $present-call)
      local.get 0 local.get 1 local.get 2 i32.const 8 call_indirect (type $present-call))
    (func (export "eread") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 9 call_indirect (type $read)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "invoke" (core func $shim-invoke))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "future" (core func $shim-future))
  (alias core export $shim-i "drop" (core func $shim-drop))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new-set" (core func $shim-new-set))
  (alias core export $shim-i "join" (core func $shim-join))
  (alias core export $shim-i "request" (core func $shim-request))
  (alias core export $shim-i "present" (core func $shim-present))
  (alias core export $shim-i "eread" (core func $shim-eread))
  (core instance $host
    (export "invoke" (func $shim-invoke)) (export "read" (func $shim-read))
    (export "future" (func $shim-future)) (export "drop" (func $shim-drop))
    (export "done" (func $shim-done)) (export "new-set" (func $shim-new-set))
    (export "join" (func $shim-join)) (export "request" (func $shim-request))
    (export "present" (func $shim-present)) (export "eread" (func $shim-eread)))
  (core module $guest
    (import "host" "invoke" (func $invoke (param i32 i32) (result i32)))
    (import "host" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "host" "future" (func $future (param i32 i32) (result i32)))
    (import "host" "drop" (func $drop (param i32)))
    (import "host" "done" (func $done (param i32 i32 i32 i32)))
    (import "host" "new-set" (func $new-set (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (import "host" "request" (func $request (param i32 i32) (result i32)))
    (import "host" "present" (func $present (param i32 i32 i32) (result i32)))
    (import "host" "eread" (func $eread (param i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    ;; 128 resource (57), 192 "read", 208 reason, 224 params, 400 one action.
    ;; 1536 request result. 8192 holds the grant id. 10240 is the document.
    ;; 2300 is the document prefix, 2340 the suffix, 2500 the media type.
    (data (i32.const 128) "localhost://Local/SharedByLocalUsersAndBots/Home/note.txt")
    (data (i32.const 192) "read")
    (data (i32.const 208) "to read")
    (data (i32.const 224) "{\"max_bytes\":64}")
    (data (i32.const 400) "\c0\00\00\00\04\00\00\00")
    (data (i32.const 720) "s1s2s3s4s5s6s7s8s9sa")
    (data (i32.const 856) "ok")
    (data (i32.const 2300) "{\"frame\":[{\"image\":{\"grant\":\"")
    (data (i32.const 2340) "\"}}]}")
    (data (i32.const 2500) "application/vnd.elastos.ui+json;v=0")
    (global $heap (mut i32) (i32.const 24576))
    (global $set (mut i32) (i32.const 0))
    (global $kind (mut i32) (i32.const 0))
    (global $expect (mut i32) (i32.const 0))
    (global $stream (mut i32) (i32.const 0))
    (global $future (mut i32) (i32.const 0))
    (global $got (mut i32) (i32.const 0))
    (global $glen (mut i32) (i32.const 0))
    (global $events (mut i32) (i32.const 0))
    (global $dlen (mut i32) (i32.const 0))
    (global $denied (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ptr i32) (local $mask i32)
      local.get 2 i32.const 1 i32.sub local.set $mask
      global.get $heap local.get $mask i32.add
      local.get $mask i32.const -1 i32.xor
      i32.and local.set $ptr
      local.get $ptr local.get 3 i32.add global.set $heap
      local.get $ptr)
    (func $eq (param $ptr i32) (param $len i32) (param $at i32) (param $n i32) (result i32)
      (local $i i32)
      local.get $len local.get $n i32.ne if i32.const 0 return end
      (loop $scan
        local.get $i local.get $n i32.eq if i32.const 1 return end
        local.get $ptr local.get $i i32.add i32.load8_u
        local.get $at local.get $i i32.add i32.load8_u
        i32.ne if i32.const 0 return end
        local.get $i i32.const 1 i32.add local.set $i
        br $scan)
      unreachable)
    (func $park (param $handle i32) (result i32)
      local.get $handle global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func $finish (result i32)
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
      i32.const 0)
    (func $fail (param $id i32) (result i32)
      (local $ptr i32)
      i32.const 720 local.get $id i32.const 1 i32.sub i32.const 2 i32.mul i32.add local.set $ptr
      i32.const 1 i32.const 2 local.get $ptr i32.const 2 call $done
      i32.const 0)
    (func $prepare
      i32.const 64 i32.const 128 i32.store
      i32.const 68 i32.const 57 i32.store
      i32.const 72 i32.const 192 i32.store
      i32.const 76 i32.const 4 i32.store
      i32.const 80 i32.const 1 i32.store
      i32.const 84 i32.const 8192 i32.store
      i32.const 88 global.get $glen i32.store
      i32.const 92 i32.const 224 i32.store
      i32.const 96 i32.const 16 i32.store
      i32.const 100 i32.const 0 i32.store
      i32.const 104 i32.const 0 i32.store)
    (func $begin-request (result i32)
      (local $code i32)
      i32.const 1400 i32.const 128 i32.store
      i32.const 1404 i32.const 57 i32.store
      i32.const 1408 i32.const 400 i32.store
      i32.const 1412 i32.const 1 i32.store
      i32.const 1416 i32.const 208 i32.store
      i32.const 1420 i32.const 7 i32.store
      i32.const 1400 i32.const 1536 call $request local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $after-request return end
      i32.const 4 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $after-request (result i32)
      (local $src i32) (local $n i32) (local $i i32)
      i32.const 1536 i32.load8_u i32.const 0 i32.ne if i32.const 1 call $fail return end
      i32.const 1544 i32.load local.set $src
      i32.const 1548 i32.load local.set $n
      local.get $n i32.eqz if i32.const 2 call $fail return end
      local.get $n i32.const 2048 i32.gt_u if i32.const 2 call $fail return end
      (loop $copy
        local.get $i local.get $n i32.eq if
          local.get $n global.set $glen
          call $begin-read
          return
        end
        i32.const 8192 local.get $i i32.add
        local.get $src local.get $i i32.add i32.load8_u
        i32.store8
        local.get $i i32.const 1 i32.add local.set $i
        br $copy)
      unreachable)
    (func $begin-read (result i32)
      (local $code i32)
      call $prepare
      i32.const 64 i32.const 256 call $invoke local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $after-invoke return end
      i32.const 0 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $after-invoke (result i32)
      i32.const 256 i32.load8_u i32.const 0 i32.ne if i32.const 3 call $fail return end
      i32.const 260 i32.load i32.const 264 i32.load i32.const 856 i32.const 2 call $eq
      i32.eqz if i32.const 4 call $fail return end
      i32.const 268 i32.load8_u i32.const 1 i32.ne if i32.const 5 call $fail return end
      i32.const 276 i32.load i32.eqz if i32.const 5 call $fail return end
      i32.const 280 i32.load global.set $stream
      i32.const 284 i32.load global.set $future
      i32.const 0 global.set $got
      call $read-more)
    (func $read-more (result i32)
      (local $code i32)
      global.get $stream i32.const 320 i32.const 64 call $read local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 1 global.set $kind
        i32.const 2 global.set $expect
        global.get $stream call $park
        return
      end
      local.get $code call $on-read)
    (func $on-read (param $code i32) (result i32)
      (local $tag i32) (local $n i32)
      local.get $code i32.const 15 i32.and local.set $tag
      local.get $code i32.const 4 i32.shr_u local.set $n
      local.get $tag i32.eqz
      if
        local.get $n i32.eqz if i32.const 6 call $fail return end
        global.get $got local.get $n i32.add i32.const 64 i32.gt_u if i32.const 6 call $fail return end
        global.get $got local.get $n i32.add global.set $got
        call $read-more
        return
      end
      local.get $tag i32.const 1 i32.eq
      if
        local.get $n i32.const 0 i32.ne if i32.const 7 call $fail return end
        global.get $got i32.eqz if i32.const 8 call $fail return end
        call $read-trailer
        return
      end
      i32.const 9 call $fail)
    (func $read-trailer (result i32)
      (local $code i32)
      global.get $future i32.const 512 call $future local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 2 global.set $kind
        i32.const 4 global.set $expect
        global.get $future call $park
        return
      end
      local.get $code call $on-trailer)
    (func $on-trailer (param $code i32) (result i32)
      local.get $code i32.const 15 i32.and i32.const 0 i32.ne if i32.const 10 call $fail return end
      i32.const 512 i32.load8_u i32.const 0 i32.ne if i32.const 3 call $fail return end
      global.get $stream call $drop
      call $begin-present)
    (func $put (param $dst i32) (param $src i32) (param $n i32)
      (local $i i32)
      (loop $bytes
        local.get $i local.get $n i32.eq if return end
        local.get $dst local.get $i i32.add
        local.get $src local.get $i i32.add i32.load8_u
        i32.store8
        local.get $i i32.const 1 i32.add local.set $i
        br $bytes)
      unreachable)
    (func $present-image (result i32)
      ;; One image block at 10240. The grant id already sits at 8192.
      i32.const 10240 i32.const 6 i32.store8
      i32.const 10244 i32.const 8192 i32.store
      i32.const 10248 global.get $glen i32.store
      i32.const 10252 i32.const 0 i32.store
      i32.const 10256 i32.const 0 i32.store
      i32.const 10240 i32.const 1 i32.const 4608 call $present)
    (func $begin-present (result i32)
      (local $code i32)
      call $present-image local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $after-present return end
      i32.const 3 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $after-present (result i32)
      i32.const 4608 i32.load8_u i32.const 0 i32.ne if i32.const 6 call $fail return end
      call $begin-event)
    (func $begin-event (result i32)
      (local $code i32)
      global.get $events i32.const 22000 i32.const 1 call $eread local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 5 global.set $kind
        i32.const 2 global.set $expect
        global.get $events call $park
        return
      end
      local.get $code call $on-event)
    (func $on-event (param $code i32) (result i32)
      ;; The second present was denied. Any later event, including the close,
      ;; ends the guest. The empty place stays until then.
      global.get $denied i32.eqz if else call $finish return end
      local.get $code i32.const 15 i32.and i32.const 0 i32.ne if i32.const 8 call $fail return end
      ;; opened and closed carry no text. Only grant-revoked (tag 3) continues.
      i32.const 22000 i32.load8_u i32.const 3 i32.ne
      if call $begin-event return end
      call $begin-present2)
    (func $begin-present2 (result i32)
      (local $code i32)
      i32.const 10240 i32.const 1 i32.const 4608 call $present local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $after-present2 return end
      i32.const 6 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $after-present2 (result i32)
      i32.const 4608 i32.load8_u i32.const 0 i32.eq if i32.const 7 call $fail return end
      i32.const 1 global.set $denied
      call $begin-event)
    (func (export "run") (param $events i32) (result i32)
      local.get $events global.set $events
      call $new-set global.set $set
      call $begin-request)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $event global.get $expect i32.ne if i32.const 9 call $fail return end
      global.get $kind i32.const 4 i32.eq
      if
        local.get $result i32.const 2 i32.ne if i32.const 1 call $fail return end
        call $after-request
        return
      end
      global.get $kind i32.const 0 i32.eq
      if
        local.get $result i32.const 2 i32.ne if i32.const 4 call $fail return end
        call $after-invoke
        return
      end
      global.get $kind i32.const 1 i32.eq if local.get $result call $on-read return end
      global.get $kind i32.const 2 i32.eq if local.get $result call $on-trailer return end
      global.get $kind i32.const 3 i32.eq
      if
        local.get $result i32.const 2 i32.ne if i32.const 6 call $fail return end
        call $after-present
        return
      end
      global.get $kind i32.const 5 i32.eq if local.get $result call $on-event return end
      global.get $kind i32.const 6 i32.eq
      if
        local.get $result i32.const 2 i32.ne if i32.const 7 call $fail return end
        call $after-present2
        return
      end
      i32.const 9 call $fail))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $invoke (canon lower (func $invoke-f) (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $read (canon stream.read $body (memory $memory) async))
  (core func $future (canon future.read $trailer (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $drop (canon stream.drop-readable $body))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new-set (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core func $cap-request (canon lower (func $request-f) (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $present (canon lower (func $present-f) (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $eread (canon stream.read $events (memory $memory) (realloc $realloc) async))
  (core module $fix
    (import "" "0" (func $invoke (param i32 i32) (result i32)))
    (import "" "1" (func $read (param i32 i32 i32) (result i32)))
    (import "" "2" (func $future (param i32 i32) (result i32)))
    (import "" "3" (func $drop (param i32)))
    (import "" "4" (func $done (param i32 i32 i32 i32)))
    (import "" "5" (func $new-set (result i32)))
    (import "" "6" (func $join (param i32 i32)))
    (import "" "7" (func $request (param i32 i32) (result i32)))
    (import "" "8" (func $present (param i32 i32 i32) (result i32)))
    (import "" "9" (func $eread (param i32 i32 i32) (result i32)))
    (import "" "$imports" (table 10 funcref))
    (elem (i32.const 0) func $invoke $read $future $drop $done $new-set $join $request $present $eread))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args
    (export "0" (func $invoke)) (export "1" (func $read))
    (export "2" (func $future)) (export "3" (func $drop))
    (export "4" (func $done)) (export "5" (func $new-set))
    (export "6" (func $join)) (export "7" (func $cap-request))
    (export "8" (func $present)) (export "9" (func $eread))
    (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run)
    (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
