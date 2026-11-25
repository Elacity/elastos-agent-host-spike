;; Sleeps on the clock, then waits on the events stream.
(component
  (import "elastos:bus/clock@2.0.0" (instance $clock
    (export "now-ms" (func (result u64)))
    (export "sleep-until-ms" (func async (param "deadline" u64)))))
  (import "elastos:bus/types@2.0.0" (instance $types
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "conflict" string)
      (case "internal" string)))
    (export "bus-error" (type (eq $error)))
    (type $grant-id string)
    (export "grant-id" (type (eq $grant-id)))
    (type $event (variant (case "stop-requested") (case "user-input" (list u8))
      (case "message" (list u8)) (case "grant-revoked" $grant-id)))
    (export "event" (type (eq $event)))))
  (alias export $clock "now-ms" (func $now-f))
  (alias export $clock "sleep-until-ms" (func $sleep-f))
  (alias export $types "bus-error" (type $error))
  (alias export $types "event" (type $event))
  (type $events (stream $event))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" $events) (result $reply)))
  (core module $shim
    (type $sleep (func (param i64) (result i32)))
    (type $now (func (result i64)))
    (type $read (func (param i32 i32 i32) (result i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (type $new (func (result i32)))
    (type $join (func (param i32 i32)))
    (table (export "table") 6 funcref)
    (func (export "sleep") (type $sleep)
      local.get 0 i32.const 0 call_indirect (type $sleep))
    (func (export "now") (type $now)
      i32.const 1 call_indirect (type $now))
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 2 call_indirect (type $read))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 3 call_indirect (type $done))
    (func (export "new") (type $new)
      i32.const 4 call_indirect (type $new))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 5 call_indirect (type $join)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "sleep" (core func $shim-sleep))
  (alias core export $shim-i "now" (core func $shim-now))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new" (core func $shim-new))
  (alias core export $shim-i "join" (core func $shim-join))
  (core instance $host
    (export "sleep" (func $shim-sleep))
    (export "now" (func $shim-now))
    (export "read" (func $shim-read))
    (export "done" (func $shim-done))
    (export "new" (func $shim-new))
    (export "join" (func $shim-join)))
  (core module $guest
    (import "host" "sleep" (func $sleep (param i64) (result i32)))
    (import "host" "now" (func $now (result i64)))
    (import "host" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "host" "done" (func $done (param i32 i32 i32 i32)))
    (import "host" "new" (func $new (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (memory (export "memory") 1)
    (global $heap (mut i32) (i32.const 1024))
    (global $events (mut i32) (i32.const 0))
    (global $set (mut i32) (i32.const 0))
    (global $phase (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $old i32)
      global.get $heap local.tee $old
      local.get 3 i32.add global.set $heap
      local.get $old)
    (func $park (param $handle i32) (result i32)
      local.get $handle global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func $finish (result i32)
      call $now drop
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
      i32.const 0)
    (func $after-sleep (result i32)
      call $finish)
    (func $begin (result i32)
      (local $code i32)
      ;; 400 ms on this guest's clock. The test's tick cap is shorter.
      i64.const 400 call $sleep local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $after-sleep return end
      i32.const 0 global.set $phase
      local.get $code i32.const 4 i32.shr_u call $park)
    (func (export "run") (param $stream i32) (result i32)
      local.get $stream global.set $events
      call $new global.set $set
      call $begin)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      global.get $phase i32.const 0 i32.eq
      if
        local.get $result i32.const 15 i32.and i32.const 2 i32.ne
        if unreachable end
        call $after-sleep
        return
      end
      local.get $result i32.const 15 i32.and i32.eqz
      if call $after-sleep return end
      call $finish))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $sleep (canon lower (func $sleep-f) async))
  (core func $now (canon lower (func $now-f)))
  (core func $read (canon stream.read $events (memory $memory) (realloc $realloc) async))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core module $fix
    (import "" "0" (func $sleep (param i64) (result i32)))
    (import "" "1" (func $now (result i64)))
    (import "" "2" (func $read (param i32 i32 i32) (result i32)))
    (import "" "3" (func $done (param i32 i32 i32 i32)))
    (import "" "4" (func $new (result i32)))
    (import "" "5" (func $join (param i32 i32)))
    (import "" "$imports" (table 6 funcref))
    (elem (i32.const 0) func $sleep $now $read $done $new $join))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args
    (export "0" (func $sleep))
    (export "1" (func $now))
    (export "2" (func $read))
    (export "3" (func $done))
    (export "4" (func $new))
    (export "5" (func $join))
    (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run) (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
