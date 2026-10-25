# Agent-host spike

One ElastOS Component guest. It folds a two-turn journal inside Wasmtime,
compacts the tail, and exits. A read proposal with no grant stays `denied`
and is not dispatched. Cancel before dispatch stays `cancelled` and does not
run. Cancel after dispatch leaves that step where it is. A snapshot of the
workspace, the time, and the open files appends after the head and does not
start a series. A checkpoint copies the model bytes before a step. Cancel
after that copy does not dispatch, and a crash keeps its settlement word.
A skill of at most 4000 bytes appends after the head. Over budget leaves the
journal unchanged. Compaction keeps that skill. It does not add an
icon to Home, call a model, or call a provider.

The journal rules under test: appending keeps the same series, and the first
system node stays byte-for-byte the same. A head rewrite starts a new series.
Compaction may replace the tail with one shorter user checkpoint, and it
refuses a summary that does not shrink. Node 0 is never the summary. The
checkpoint stays in the model view. Compaction opens, then commits.
A crash between those two restores the saved bytes and the series. The
summary is not kept. A crash before
dispatch stays `not started`. A crash after dispatch is `settlement_unknown`.
That step is not dispatched again, and the crash does not start a new series.
Recording the visible journal and reading it back produces the same bytes.
The series epoch, the step list, and the turn list are not part of those
bytes. Opening a turn records its own id and leaves the series where it is.
Two steps on that turn share the epoch. Turn and step markers stay in their
own record. `derive` omits them. The log encoder still writes them when they
are the nodes it is given. An assistant line is role tag 3. A tool result
is role tag 4. Replay restores both. An empty assistant line stays in those
bytes and in replay. The model view omits that empty line and keeps an empty
tool result. One tool result may be recorded for a step. That result enters
the model view. A step with no result stays in the marker log, and the view
omits it. A second result for the same step leaves the journal unchanged. A read
observation appends the resource, the version, and the SHA-256 of the text.
Replay restores that record. The model view omits it. An empty resource is
refused. An edit of a resource that has not been read, or of a version that
is no longer current, creates no step and writes nothing. The old text
must occur once in the observed text. Zero times and more than once create
no step. Replay still has the observation. A later write stays prepared
until the earlier write has a result. Each write keeps its own effect id.
A provider write may be asked only when the step has a grant and the
version is still current. The guest does not apply the write. A run
proposal stores a `localhost://` project and its arguments as data. A host
path creates no step. Cancel before dispatch does not start a process.
A restore writes an observed version back through the same granted write
path as an edit. An unknown version is refused. A version that is no longer
current is refused until that version is read again. A hosted proposal
names a model resource and has no secret field. A missing grant denies it
the same way a read is denied.
A child proposal records a resource under the parent's resource. It does
not receive the parent's grant. `child-grant` is a test token, not a
Runtime grant. A project proposal stores
`localhost://Users/<root>/Projects/<name>` and no host path. The local
engine cache stays off, and the idle release stays 60 seconds. A
project tree hash changes when a file that is not the entrypoint changes.
The capsule admission hash is still the entrypoint file. A scaffold write
of an empty observed file follows the version rules and does not apply. A
run seat is `microvm`. A run result is an exit code and a log of at most
4000 bytes, recorded only after a granted dispatch. The success log
recorded here is `init: hello from vm smoke test`, and that line belongs
to the program `true`. A failed command is recorded as exit 1 and
`init: command failed`, and that line belongs to `false`. A file list
belongs to `files`. A note sentence belongs to `note`, or to the edited
project test when it prints the sentence with the digest. One grant may
cover `files`, `note`, and the Rust test. Each keeps its own effect id,
and a result cannot move from one program to another. A compiled Rust test is
recorded as the project digest and `test result: ok`,
or as `test result: FAILED` with exit 101. An exit code that
disagrees with that line is refused. A granted edit becomes the current
text in the journal and does not write a file on the host. A version
that moved after the proposal is refused. The new text is still there
after the log is replayed. A file list in the machine names
`index.html`, `style.css`, and `notes.txt` and does not name a host
path. The note text is `hello from the project`. Retyping it to
`hello again` changes the digest, and the previous digest is refused.
The machine may print `project note` plus that current sentence. An
older sentence, or a host path, is refused. A file list must name every file the project has been shown, and
no file it has not. A repeated name still counts once. A crash after the edit
was sent leaves the old sentence in place. Cancel before it is sent
does the same. Cancel after it is sent does not take it back. A crash after the
result is stored does not erase it. An open scaffold still blocks a
later note rewrite. Cancelling that scaffold lets the rewrite land, and
the note text stays the old sentence until the rewrite itself is sent.
Sending the scaffold still leaves the page empty, and that refusal
does not keep a later note rewrite waiting. A write whose version
moved is refused the same way. A new read uses a higher version.
Reading an older version again is allowed only when the text still
matches that version. After that older note is current again, a later
result must quote it, and the rewritten sentence is refused. An edit
prepared against the rewritten sentence does not land. A fresh edit of
the sentence that is current now does land. Reading the log back still
shows that sentence. A shorter log keeps that file read, still accepts a result that
quotes it, and still accepts an edit of that sentence. A second
shortening keeps the older version, so that sentence can be current
again. A crash during that shortening leaves both sentences in place.
The whole project stays too: the file list, the digest, and a skill.
The workspace snapshot stays as well. A host path is not stored
there, and it is not stored as a skill, a file read, or the shortening
summary. A goal and a to-do stay after that shortening. They do not grant.
An inbox answer does not mint a grant. Deny, or an allow with no
grant, leaves the step denied. A second answer does not replace the
first, and it does not authorize another step. The answer name stays
in the log. The grant string does not. Cancel before send still stops
that step. A spill pointer names a file that has been read, and the version of
that read. A later edit does not move the pointer. Reading the pointer
returns the text of that version. A missing version is skipped, and
the earlier pointer is used. A newer pointer to the edited text is
the one that is read. The older version stays. A pointer for the
stylesheet does not change the note. A child cannot be answered with
the parent's grant. That refusal adds no inbox line. The line appears
when the child receives its own grant, and sending the child does not
send the parent. Cancelling that child does not cancel the parent,
and the inbox line stays. A crash after the child is sent leaves it
unfinished and leaves the parent prepared. A crash after the child
has a result does not erase that result. Reading the log back, and
shortening it, still returns that file. The same command waits
until the first one has a result. A different command can run beside
it. The same command on another project can run beside it too.
Two different test names can run together. An exact repeat of a test
name waits. Once that name has a result, it can run again. The other
name stays held. A crash of one test name holds only that name.
The other name stays where it was, and a finished result stays. After
that crash, a result on the other name lets that name run again. The
crashed name still holds. Cancelling the waiting copy does not free
the crashed name. The other name stays sent. The same crashed name
can finish on another project. This project stays held. That failure
is in the log. The grant is not. The next copy on that project can
run. This project stays held. A crash of that next copy holds only
that project. This project stays where it was, and the finished
failure stays. A result on this project's other test lets that name
run again. Neither crash is freed. Both lines stay in the log. The
grant does not. The program `true` can finish on each crashed project.
An exact repeat of `true` waits. The hello line stays in the log
beside the test lines. Neither crash is freed. The grant does not.
The program `false` can finish on each crashed project. An exact
repeat waits. The hello line is refused for it, and its line is
refused for the open `true`. Neither crash is freed. The grant does not.
The edited-project test can run while the ready test is still open
and the missing-piece test is crashed. An exact repeat waits. A note
line is refused until that note has been read. The pass line can still
be recorded. Neither crash is freed. The grant does not. Once that
note has been read, the open copy can quote it. An older sentence
and a host path are refused. The note text stays. Neither crash is
freed. The grant does not. The open file list can name that note,
and only that file. A missing file, an extra line, and a host path
are refused. An exact repeat waits, then it can be sent. The other
project cannot name this file. Neither crash is freed. The grant does not.
Once a second file has been read, the open list must name both. Naming
only the note is refused. The other project still cannot name them.
Neither crash is freed. The grant does not. The open ready test
can quote the digest of those two files. A digest that includes a
file that was not read is refused. The other project cannot quote
this digest. Neither crash is freed. The grant does not. After
the stylesheet is read again, that digest is refused and the new one
is required. The note text stays. Neither crash is freed. The grant
does not. The file list must still name both files. Naming only the
note is refused. Neither crash is freed. An unread file stays out
of the list. The other project still cannot name these files. Once
the page is read, the list must name it too. Leaving it out is
refused, and the digest must include it. The other project still
cannot name these files. Neither crash is freed. The grant does not.
Once the page is read again, the old digest is refused and the new
one is required. The file names stay the same. Leaving the page out
of the list is still refused. Neither crash is freed. The grant does not.
Reading the older page again makes that text current. A different
wording of the newer version is refused. The digest follows the
current page. The newer wording stays stored. Neither crash is freed.
The grant does not. Reading the log back keeps the current page and
the newer wording. The grant is not in that log. A host path, a
blank name, and a path with a space add nothing. Shortening without
a head leaves the log as it is. The list and the digest still follow
the current page. The grant is not in the log. With a head, shortening
keeps the reads and the head. A second shortening that does not shrink
is refused, and so is a summary that is a host path. The list and the
digest still follow the current page. Reading the log back keeps the
head, the current page, and the newer wording. The grant is not in
the log. The version list names both page wordings. Restoring the
current one records a proposal and does not change the page. Restoring
the other wording is refused until it is read again. Sending that
proposal with no grant is denied. The list is not a grant.
The Home GUI Versions menu shows that same list from the Home summary and still does not grant.
A pointer must name a file inside that step's
own folder. The file text stays
in the read, and the grant is not in the pointer. An unread name is
refused.
After a rewrite that does land, a later note read
must say `hello again`, and the old project digest is refused. An
unknown command is exit 1 and `init: command refused`. This guest
does not boot that machine, and it does not run the `cargo` command.
The exit code is read from the machine's console. The provider runs
`vm-smoke` with a test name. A result for `cargo test` is refused
because that program is not in the image. The proposal may still
name it. A host path in the log is refused. No process is started.
Recording a
read does not change those bytes or the series. Cancelling a step does not
change them either. A snapshot changes the bytes by appending, and node 0
stays the same record. A checkpoint matches the bytes again when cancel or
a crash stops the step. A skill changes the bytes by appending, and node 0
stays the same record.

## Build and test

From this directory:

```bash
rustup target add wasm32-unknown-unknown
./verify.sh
```

`cargo test` proves the fold. The `.wasm` file is the guest Runtime can load.
Both are local. This directory stays outside `capsules/`, the Cargo workspace,
and CI.

## Run in Wasmtime, still on this machine

`./run-local.sh` builds the guest and loads it with the Runtime's own Wasmtime.
The guest runs two turns, compacts the tail, and exits. This does not start `elastos serve`, does
not open the Home data directory, and does not publish anything.

## Run beside a local Runtime

The Component ABI has no stdout. A successful run prints only the host exit
line. Start the operator Runtime in one terminal, then run the guest from
another:

```bash
./elastos/target/release/elastos serve
```

```bash
./elastos/target/release/elastos run "$PWD/examples/agent-host"
```

Success ends with:

```text
[run] Component capsule 'agent-host' exited
```

That command is an operator action. Home's window does not list this guest.
