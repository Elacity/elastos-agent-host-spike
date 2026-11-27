;; One capabilities.request, after an events read has gone pending.
(component
  (import "elastos:bus/types@2.0.0" (instance $types
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
      (case "message" (list u8)) (case "grant-revoked" $grant-id)))
    (export "event" (type (eq $event)))))
  (alias export $types "bus-error" (type $error))
  (alias export $types "grant" (type $grant))
  (alias export $types "event" (type $event))
  (type $request-result (result $grant (error $error)))
  (type $cap-request (func async (param "resource" string) (param "actions" (list string))
    (param "reason" string) (result $request-result)))
  (import "elastos:bus/capabilities@2.0.0" (instance $caps
    (export "grant" (type (eq $grant)))
    (export "bus-error" (type (eq $error)))
    (export "request" (func (type $cap-request)))))
  (alias export $caps "request" (func $request-f))
  (type $events (stream $event))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" $events) (result $reply)))
  (core module $shim
    (type $request (func (param i32 i32) (result i32)))
    (type $read (func (param i32 i32 i32) (result i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (type $new (func (result i32)))
    (type $join (func (param i32 i32)))
    (table (export "table") 5 funcref)
    (func (export "request") (type $request)
      local.get 0 local.get 1 i32.const 0 call_indirect (type $request))
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 1 call_indirect (type $read))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 2 call_indirect (type $done))
    (func (export "new") (type $new)
      i32.const 3 call_indirect (type $new))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 4 call_indirect (type $join)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "request" (core func $shim-request))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new" (core func $shim-new))
  (alias core export $shim-i "join" (core func $shim-join))
  (core instance $host
    (export "request" (func $shim-request)) (export "read" (func $shim-read))
    (export "done" (func $shim-done)) (export "new" (func $shim-new))
    (export "join" (func $shim-join)))
  (core module $guest
    (import "host" "request" (func $request (param i32 i32) (result i32)))
    (import "host" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "host" "done" (func $done (param i32 i32 i32 i32)))
    (import "host" "new" (func $new (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (memory (export "memory") 1)
    (data (i32.const 128) "localhost://Local/note.txt")
    (data (i32.const 192) "read")
    (data (i32.const 208) "because")
    (data (i32.const 400) "\c0\00\00\00\04\00\00\00")
    (global $heap (mut i32) (i32.const 4096))
    (global $events (mut i32) (i32.const 0))
    (global $set (mut i32) (i32.const 0))
    (global $saw-stream (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ptr i32) (local $mask i32)
      local.get 2 i32.const 1 i32.sub local.set $mask
      global.get $heap local.get $mask i32.add
      local.get $mask i32.const -1 i32.xor
      i32.and local.set $ptr
      local.get $ptr local.get 3 i32.add global.set $heap
      local.get $ptr)
    (func $park (param $handle i32) (result i32)
      local.get $handle global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func $finish (result i32)
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
      i32.const 0)
    (func $ask (result i32)
      (local $code i32)
      i32.const 1400 i32.const 128 i32.store
      i32.const 1404 i32.const 26 i32.store
      i32.const 1408 i32.const 400 i32.store
      i32.const 1412 i32.const 1 i32.store
      i32.const 1416 i32.const 208 i32.store
      i32.const 1420 i32.const 7 i32.store
      i32.const 1400 i32.const 1536 call $request local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $stay return end
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $stay (result i32)
      (local $code i32)
      global.get $saw-stream i32.eqz
      if
        global.get $set i32.const 4 i32.shl i32.const 2 i32.or
        return
      end
      global.get $events i32.const 8 i32.const 1 call $read local.set $code
      local.get $code i32.const -1 i32.eq
      if
        global.get $events call $park
        return
      end
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func (export "run") (param $stream i32) (result i32)
      (local $code i32)
      local.get $stream global.set $events
      call $new global.set $set
      global.get $events i32.const 8 i32.const 1 call $read local.set $code
      local.get $code i32.const -1 i32.eq
      if
        global.get $events global.get $set call $join
      end
      call $ask)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $event i32.const 2 i32.eq
      if
        i32.const 1 global.set $saw-stream
      end
      local.get $event i32.const 1 i32.eq
      if
        local.get $result i32.const 2 i32.ne
        if unreachable end
        call $stay
        return
      end
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $request (canon lower (func $request-f) (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $read (canon stream.read $events (memory $memory) (realloc $realloc) async))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core module $fix
    (import "" "0" (func $request (param i32 i32) (result i32)))
    (import "" "1" (func $read (param i32 i32 i32) (result i32)))
    (import "" "2" (func $done (param i32 i32 i32 i32)))
    (import "" "3" (func $new (result i32)))
    (import "" "4" (func $join (param i32 i32)))
    (import "" "$imports" (table 5 funcref))
    (elem (i32.const 0) func $request $read $done $new $join))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args
    (export "0" (func $request)) (export "1" (func $read))
    (export "2" (func $done)) (export "3" (func $new))
    (export "4" (func $join))
    (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run) (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
