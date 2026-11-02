#!/usr/bin/env python3
"""Cross-artifact semantic validator for a complete or resumable STRIDE run."""
from __future__ import annotations
import argparse, hashlib, json, math, re, sys
from pathlib import Path

# `python3 -I` drops the script's own folder from sys.path; the sibling modules are imported by name.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from digest import canonical, candidate_issue_record, sha  # noqa: E402
from jsonschema_subset import validate  # noqa: E402
from validate_report import extract_base_findings, parse_tables, validate_markdown, validate_quotes, verifier_result_errors  # noqa: E402

ROOT=Path(__file__).resolve().parents[1]  # the skill root: read-only, holds VERSION and assets/schemas/
SCHEMAS=ROOT/"assets"/"schemas"
RUBRIC_RANK={"SR-Critical":0,"SR-High":1,"SR-Medium":2,"SR-Low":3,"SR-Undetermined":4}
def sweep_ordering(candidate:dict)->tuple:
    anchor=min((item["relativePath"],item["locator"]) for item in candidate["evidence"])
    lens=candidate["lensQuestion"]
    substance={key:value for key,value in candidate.items() if key!="candidateId"}
    return (0 if candidate["uncoveredInteraction"] else 1,RUBRIC_RANK[candidate["rubricCell"]],1 if lens is None else 0,lens or "",anchor[0],anchor[1],candidate["claim"],canonical(substance))
def load(path:Path): return json.loads(path.read_text(encoding="utf-8"))
def safe(base:Path, relative:str, errors:list[str], label:str)->Path:
    path=(base/relative).resolve()
    try: path.relative_to(base.resolve())
    except ValueError: errors.append(f"{label} escapes root: {relative}")
    return path
def check_schema(data:object,name:str,errors:list[str])->None:
    schema=load(SCHEMAS/name)
    errors.extend(f"{name}: {item}" for item in validate(data,schema))
def check_file_record(base:Path,record:dict,errors:list[str])->Path:
    path=safe(base,record["path"],errors,"artifact")
    if not path.is_file(): errors.append(f"artifact missing: {record['path']}"); return path
    actual,size=sha(path),path.stat().st_size
    if actual!=record["sha256"]: errors.append(f"artifact digest mismatch: {record['path']} (recorded {record['sha256']}, recomputed {actual})")
    if size!=record["bytes"]: errors.append(f"artifact byte count mismatch: {record['path']} (recorded {record['bytes']}, actual {size})")
    return path

def corpus_prefix(envelope:dict)->str|None:
    """The corpus subtree, expressed relative to the run root, when it sits inside it."""
    docs_root,run_root=envelope["docsRoot"].strip("/"),envelope["runRoot"].strip("/")
    if docs_root==run_root: return ""
    return docs_root[len(run_root)+1:] if docs_root.startswith(run_root+"/") else None

def open_replies(manifest:dict,run:Path,ledger:dict|None=None)->set[str]:
    """The reply files that may sit in `inbox/` right now: the one that each delegated unit still open is writing.

    A delegated sweep or verifier writes its reply to a file there and `stride_run.py` ingests it and removes it, so the file
    of a unit that is open is not stray. Nothing else is allowed: a file of a unit that is finished (a role that rewrote its
    reply after it was recorded), of a unit that was never opened, of a run that failed, or of any name, is pollution, and
    this holds for a finished stage 1, stage 2 or verify-one run as for a finishing full run."""
    if manifest["status"]=="failed": return set()
    bound,stages={a["path"] for a in manifest["artifacts"]},manifest["stages"]
    allowed=set()
    if manifest["mode"] in {"full","stage3"} and stages["stage1"]["state"]=="accepted" and stages["stage2"]["state"]=="accepted" and "stage-3/sweep-result.json" not in bound:
        allowed.add("inbox/sweep.json")
    for entry in (ledger or {}).get("entries",[]):
        last=entry["attempts"][-1] if entry["attempts"] else None
        if entry["state"] in {"attempt-1-invoked","attempt-2-invoked"} and last and last["outcome"]=="invoked" and last["resultPath"] is None:
            allowed.add(f"inbox/verifier-{entry['queueKey']}-{last['number']}.json")
    if manifest["mode"]=="verify-one":
        for number in (2,1):                        # the open attempt is the latest one that has a request and no result
            request,result=f"verify-one/attempt-{number}-request.json",f"verify-one/attempt-{number}-result.json"
            if request in bound:
                try: key=load(run/request)["queueKey"]
                except (OSError,ValueError,KeyError,TypeError): key=None
                if result not in bound and key: allowed.add(f"inbox/verifier-{key}-{number}.json")
                break
    return allowed

def stray_errors(run:Path,expected:set[str],prefix:str|None,replies:set[str]=frozenset())->list[str]:
    """The run root holds the run's artifacts and nothing else.

    Scratch files, helper scripts, and abandoned intermediates are pollution: every file must
    be referenced by the manifest, the frozen index, or the ledger. The one exception is the reply file of a
    delegated unit that is still open (`open_replies`)."""
    errors=[]
    for path in sorted(run.rglob("*")):
        if not path.is_file(): continue
        relative=path.relative_to(run).as_posix()
        if prefix is not None and (prefix=="" or relative.startswith(prefix+"/")):
            continue                                   # the corpus may sit inside the run root
        if relative in replies:
            continue
        if relative not in expected:
            errors.append(f"unreferenced file in run root: {relative}")
    return errors

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("run_root",type=Path); p.add_argument("--workspace-root",type=Path,required=True); args=p.parse_args()
    run=args.run_root.resolve(); workspace=args.workspace_root.resolve(); errors=[]
    manifest_path=run/"run-manifest.json"
    if not manifest_path.is_file(): raise SystemExit("run-manifest.json missing")
    manifest=load(manifest_path)
    if isinstance(manifest,dict) and manifest.get("schemaVersion")=="1.0":
        return finish(["run manifest schema 1.0 predates this skill: 1.1 adds the run mode and the dispatch record and replaces the harness isolation methods with host-subagent; start a new run with stride_run.py init"])
    check_schema(manifest,"run-manifest-1.1.json",errors)
    # envelope.json is the operator's run input; everything else must be referenced.
    expected_files={"run-manifest.json","envelope.json"}
    installed_version=(ROOT/"VERSION").read_text(encoding="utf-8").strip()
    if manifest.get("packageVersion")!=installed_version:
        errors.append(f"run packageVersion {manifest.get('packageVersion')!r} does not match installed {installed_version!r}")
    if errors: return finish(errors)
    envelope=manifest["envelope"]
    environment=manifest["environment"]
    if environment["validatedModelTier"]=="measured" and not environment["validationEvidence"]:
        errors.append("measured model tier requires validationEvidence")
    if environment["validatedModelTier"]=="measured":
        effort=environment.get("reasoningEffort")
        if effort is None:
            errors.append("measured model tier requires environment.reasoningEffort so the run is reproducible")
        else:
            vague=sorted(role for role,level in effort.items() if level=="unspecified")
            if vague: errors.append("measured model tier requires a stated reasoning effort for every role, not 'unspecified': "+", ".join(vague))
    for schema_name, recorded_digest in manifest["environment"]["schemaDigests"].items():
        schema_path=SCHEMAS/schema_name
        if not schema_path.is_file():
            errors.append(f"installed schema digest mismatch: {schema_name} (schema file absent)")
        elif sha(schema_path)!=recorded_digest:
            errors.append(f"installed schema digest mismatch: {schema_name} (recorded {recorded_digest}, installed {sha(schema_path)})")
    # Nothing in a plain skill install can confirm how a host isolates a role from inherited context, so no run may claim it:
    # host-subagent records that roles ran as host-started subagents (the host's claim, unverified), interactive-inventoried that
    # one context performed every role. inheritedResources is the coordinator's inventory of what its own context loaded.
    if envelope["resourceIsolationConfirmed"]: errors.append("resourceIsolationConfirmed must be false: nothing in this skill can confirm that a host isolates a role from inherited context (resourceIsolationMethod records the claim)")
    dispatch=manifest["dispatch"]
    expected_method={"subagent":"host-subagent","inline":"interactive-inventoried"}[dispatch["mode"]]
    if envelope["resourceIsolationMethod"]!=expected_method: errors.append(f"dispatch mode {dispatch['mode']!r} requires resourceIsolationMethod {expected_method!r}, the envelope says {envelope['resourceIsolationMethod']!r}")
    unit_ids=[record["unit"] for record in dispatch["units"]]
    if len(unit_ids)!=len(set(unit_ids)): errors.append("dispatch records repeat a unit")
    for record in dispatch["units"]:
        fallback_unit=record["unit"].startswith("verifier/") and record["unit"].endswith("/inline")
        wanted="inline" if dispatch["mode"]=="inline" or fallback_unit else "subagent"
        if record["mode"]!=wanted: errors.append(f"dispatch record {record['unit']} says {record['mode']!r} but a {dispatch['mode']} run records {wanted!r} for it")
        if fallback_unit and envelope["verificationFallback"]!="inline": errors.append(f"dispatch record {record['unit']} is an inline fallback, which the envelope forbids")
    # The envelope's runRoot must be the directory under validation: corpus_prefix() and the
    # stray-file exemption are derived from it, so a manifest naming another root could exempt
    # anything. docsRoot may sit inside runRoot, never the reverse, and never coincide.
    declared_run=(workspace/envelope["runRoot"]).resolve(); declared_docs=(workspace/envelope["docsRoot"]).resolve()
    if declared_run!=run: errors.append(f"envelope runRoot {envelope['runRoot']!r} resolves to {declared_run}, not the run root being validated ({run})")
    if declared_docs==declared_run: errors.append("docsRoot must not equal runRoot")
    elif declared_run.is_relative_to(declared_docs): errors.append("runRoot must not lie inside docsRoot")
    # envelope.json is the operator's input; the manifest must carry it unchanged.
    envelope_file=run/"envelope.json"
    if envelope_file.is_file():
        try: supplied=load(envelope_file)
        except json.JSONDecodeError: errors.append("envelope.json is not valid JSON"); supplied=None
        if supplied is not None and not isinstance(supplied,dict): errors.append("envelope.json must be a JSON object")
        elif supplied:
            for key,value in sorted(supplied.items()):
                if key not in envelope: errors.append(f"envelope.json key {key!r} is not carried by the manifest envelope")
                elif envelope[key]!=value: errors.append(f"envelope.json {key} ({value!r}) disagrees with the manifest envelope ({envelope[key]!r})")
    expected_files.add(manifest["corpus"]["manifestPath"])
    corpus_path=safe(run,manifest["corpus"]["manifestPath"],errors,"corpus manifest")
    if not corpus_path.is_file(): errors.append("corpus manifest missing"); return finish(errors)
    corpus=load(corpus_path); check_schema(corpus,"corpus-manifest-1.0.json",errors)
    corpus_paths={str(source["relativePath"]) for source in corpus.get("sources",[])}
    if sha(corpus_path)!=manifest["corpus"]["manifestSha256"]: errors.append(f"corpus manifest digest mismatch (recorded {manifest['corpus']['manifestSha256']}, recomputed {sha(corpus_path)})")
    if corpus["aggregateDigest"]!=manifest["corpus"]["aggregateDigest"]: errors.append(f"manifest/corpus aggregate digest mismatch (manifest {manifest['corpus']['aggregateDigest']}, corpus manifest {corpus['aggregateDigest']})")
    if corpus["sourceCount"]!=manifest["corpus"]["sourceCount"] or corpus["totalBytes"]!=manifest["corpus"]["totalBytes"]: errors.append("manifest/corpus source counts mismatch")
    docs=(workspace/envelope["docsRoot"]).resolve(); tuples=[]
    try: docs.relative_to(workspace)
    except ValueError: errors.append("docsRoot escapes workspace")
    for source in corpus["sources"]:
        path=safe(docs,source["relativePath"],errors,"source")
        if not path.is_file(): errors.append(f"source missing: {source['relativePath']}"); continue
        actual_sha,actual_bytes=sha(path),path.stat().st_size
        if (actual_sha,actual_bytes)!=(source["sha256"],source["bytes"]): errors.append(f"source identity mismatch: {source['relativePath']} (recorded {source['sha256']}/{source['bytes']}B, recomputed {actual_sha}/{actual_bytes}B)")
        tuples.append([source["relativePath"],actual_sha,actual_bytes])
    aggregate=hashlib.sha256(json.dumps(tuples,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
    if aggregate!=corpus["aggregateDigest"]: errors.append(f"recomputed corpus aggregate digest mismatch (recorded {corpus['aggregateDigest']}, recomputed {aggregate})")
    # The manifest must describe the whole corpus: a source it does not declare was never
    # reviewed, so every corpus-wide absence claim in the reports would be unsupported.
    if not docs.is_dir(): errors.append(f"docsRoot is not a directory: {envelope['docsRoot']}")
    else:
        for path in sorted(docs.rglob("*")):
            relative=path.relative_to(docs).as_posix()
            if path.is_symlink(): errors.append(f"corpus contains a symlink: {relative}")
            elif path.is_file() and relative not in corpus_paths: errors.append(f"undeclared corpus source (absent from the corpus manifest): {relative}")
    unreadable_source=any(source.get("fidelity")=="unreadable" for source in corpus["sources"])
    artifact_paths={}
    artifact_records=manifest["artifacts"]
    paths=[record["path"] for record in artifact_records]
    if len(paths)!=len(set(paths)): errors.append("manifest contains duplicate artifact paths")
    expected_files.update(record["path"] for record in artifact_records)
    for record in artifact_records: artifact_paths[record["path"]]=check_file_record(run,record,errors)
    verify_one=manifest["mode"]=="verify-one"          # one verifier result, no stages, no queue, no final report
    if manifest["status"]=="completed":
        if verify_one:
            if not any(re.fullmatch(r"verify-one/attempt-[12]-result\.json",path) for path in artifact_paths): errors.append("completed verify-one run lacks its bound verifier result")
        else:
            missing_required=sorted({"stage-1-review.md","stage-2-gap-review.md","final-review.md"}-set(artifact_paths))
            if missing_required: errors.append("completed run lacks mandatory artifact records: "+", ".join(missing_required))
    base_findings=[]
    for report_name,kind in [("stage-1-review.md","stage1"),("stage-2-gap-review.md","stage2"),("final-review.md","final")]:
        if report_name in artifact_paths:
            errors.extend(f"{report_name}: {item}" for item in validate_markdown(artifact_paths[report_name],kind,docs,corpus_paths,unreadable_source))
            if kind in {"stage1","stage2"}:
                extracted,_=extract_base_findings(artifact_paths[report_name],kind); base_findings.extend(extracted)
            if corpus["aggregateDigest"] not in artifact_paths[report_name].read_text(encoding="utf-8"): errors.append(f"{report_name}: bound corpus digest absent")
    stages=manifest["stages"]; status=manifest["status"]
    if status=="initializing" and any(stages[name]["state"]!="pending" for name in stages): errors.append("initializing run must have all stages pending")
    if status=="stage1" and any(stages[name]["state"]!="pending" for name in ("stage2","stage3")): errors.append("stage1 run has later-stage progress")
    if status=="stage2" and (stages["stage1"]["state"]!="accepted" or stages["stage3"]["state"]!="pending"): errors.append("stage2 run requires accepted Stage 1 and pending Stage 3")
    if status in {"stage3","finalizing","completed"} and not verify_one and any(stages[name]["state"]!="accepted" for name in ("stage1","stage2")): errors.append(f"{status} run requires accepted Stage 1 and Stage 2")
    if stages["stage1"]["state"]=="accepted" and "stage-1-review.md" not in artifact_paths: errors.append("accepted Stage 1 lacks its manifest-bound report")
    if stages["stage2"]["state"]=="accepted" and "stage-2-gap-review.md" not in artifact_paths: errors.append("accepted Stage 2 lacks its manifest-bound report")
    index_path=run/"stage-3/issue-index.json"; ledger_path=run/"stage-3/verification-ledger.json"
    stage3_summary=manifest["stage3Ledger"]
    has_index,has_ledger=index_path.is_file(),ledger_path.is_file()
    if stage3_summary is None:
        if has_index or has_ledger: errors.append("pre-ledger checkpoint has unbound Stage 3 index or ledger")
        if stages["stage3"]["state"]!="pending": errors.append("missing Stage 3 ledger requires pending Stage 3 state")
        if status in {"finalizing","completed"} and not verify_one: errors.append(f"{status} run requires a Stage 3 ledger")
        return finish(errors+stray_errors(run,expected_files,corpus_prefix(envelope),open_replies(manifest,run)))
    if status not in {"stage3","finalizing","completed","failed"}: errors.append(f"{status} run cannot carry a Stage 3 ledger")
    if not has_index or not has_ledger: errors.append("Stage 3 index or ledger missing"); return finish(errors)
    expected_files.update({"stage-3/issue-index.json","stage-3/verification-ledger.json","stage-3/sweep-result.json"})
    index,ledger=load(index_path),load(ledger_path); check_schema(index,"issue-index-1.0.json",errors); check_schema(ledger,"verification-ledger-1.0.json",errors)
    sweep_path=run/"stage-3/sweep-result.json"
    if not sweep_path.is_file(): errors.append("independent sweep result missing")
    else:
        sweep_result=load(sweep_path); check_schema(sweep_result,"sweep-result-1.0.json",errors)
        if sha(sweep_path)!=index.get("sweepResultSha256"): errors.append(f"issue index sweep-result digest mismatch (recorded {index.get('sweepResultSha256')}, recomputed {sha(sweep_path)})")
        if sweep_result.get("corpusDigest")!=corpus["aggregateDigest"]: errors.append("sweep-result corpus digest mismatch")
        errors.extend(f"sweep-result: {item}" for item in validate_quotes(sweep_result,docs,corpus_paths))
    if errors: return finish(errors)
    if index["corpusDigest"]!=corpus["aggregateDigest"] or ledger["corpusDigest"]!=corpus["aggregateDigest"]: errors.append(f"Stage 3 corpus digest mismatch (index {index['corpusDigest']}, ledger {ledger['corpusDigest']}, corpus {corpus['aggregateDigest']})")
    index_sha=sha(index_path)
    if ledger["issueIndexSha256"]!=index_sha: errors.append(f"ledger issue-index digest mismatch (recorded {ledger['issueIndexSha256']}, recomputed {index_sha})")
    items=index["items"]; n=len(items); base_items=[x for x in items if x["origin"] in {"stage1","stage2"}]; base=len(base_items); sweep=sum(x["origin"]=="stage3" for x in items)
    expected_base=[]
    for finding in base_findings:
        record=finding["blindedRecord"]
        expected_base.append({**finding,"sourceCandidateId":None,"sourceCandidateDigest":None,"issueRecordDigest":hashlib.sha256(canonical(record)).hexdigest()})
    if len(base_items)!=len(expected_base):
        errors.append(f"Stage 1/2 issue index count {len(base_items)} does not reconcile with {len(expected_base)} active report findings")
    for position,(actual,expected) in enumerate(zip(base_items,expected_base),start=1):
        projection={key:actual.get(key) for key in expected}
        if projection!=expected:
            errors.append(f"Stage 1/2 issue index item {position} does not exactly reconcile with its immutable source report")
    expected_cap=min(15,max(1,math.ceil(.20*len(expected_base))))
    if sweep_result["candidateCap"]!=expected_cap or len(sweep_result["candidates"])!=sweep:
        errors.append("sweep result cap/count does not reconcile with frozen Stage 3 items")
    if n>index["maxQueueSize"] or index["maxQueueSize"]!=envelope["maxQueueSize"]: errors.append("queue exceeds or disagrees with maxQueueSize")
    if index["baseIssueCount"]!=len(expected_base) or base!=len(expected_base) or index["sweepCandidateCount"]!=sweep or index["coverageCap"]!=expected_cap or sweep>expected_cap: errors.append("base/sweep counts or coverage cap do not reconcile")
    cost=index["costEstimate"]
    if cost!={"queueItems":n,"minimumDelegatedCalls":n,"maximumDelegatedCalls":2*n,"maximumInlineFallbacks":n if envelope["verificationFallback"]=="inline" else 0}: errors.append("queue cost estimate does not reconcile")
    keys=[x["queueKey"] for x in items]
    if len(set(keys))!=n: errors.append("duplicate queue keys")
    if [x["ordinal"] for x in items]!=list(range(1,n+1)): errors.append("queue ordinals are not contiguous")
    rank={"stage1":0,"stage2":1,"stage3":2}
    if [rank[x["origin"]] for x in items]!=sorted(rank[x["origin"]] for x in items): errors.append("queue origins are out of order")
    def ordering(item:dict):
        match=re.fullmatch(r"S[123]-([0-9]{3,})",item["issueId"])
        return (rank[item["origin"]],0 if match else 1,int(match.group(1)) if match else 0,item["issueId"].encode("utf-8"),item["sourceOccurrence"])
    if items!=sorted(items,key=ordering): errors.append("queue numeric/byte/occurrence order is invalid")
    id_counts={value:sum(item["issueId"]==value for item in items) for value in {item["issueId"] for item in items}}
    candidate_ids=[candidate["candidateId"] for candidate in sweep_result["candidates"]]
    if len(candidate_ids)!=len(set(candidate_ids)): errors.append("sweep candidate IDs are not unique")
    candidates={candidate["candidateId"]:candidate for candidate in sweep_result["candidates"]}
    ordered_candidates=sweep_result["candidates"]
    expected_candidate_ids=[f"S3-CANDIDATE-{position:03d}" for position in range(1,len(ordered_candidates)+1)]
    if candidate_ids!=expected_candidate_ids: errors.append("sweep candidate IDs do not match deterministic rank positions")
    if ordered_candidates!=sorted(ordered_candidates,key=sweep_ordering): errors.append("sweep candidates violate deterministic priority order")
    stage3_items=[item for item in items if item["origin"]=="stage3"]
    stage3_candidate_ids=[item["sourceCandidateId"] for item in stage3_items]
    if len(stage3_candidate_ids)!=len(set(stage3_candidate_ids)) or set(stage3_candidate_ids)!=set(candidate_ids): errors.append("sweep candidates and Stage 3 items are not one-to-one")
    for position,(candidate,item) in enumerate(zip(ordered_candidates,stage3_items),start=1):
        if item["sourceCandidateId"]!=candidate["candidateId"] or item["issueId"]!=f"S3-{position:03d}": errors.append(f"Stage 3 ID allocation does not follow sweep rank at position {position}")
    for item in items:
        valid_id=re.fullmatch(r"S[123]-[0-9]{3,}",item["issueId"])
        encoded=item["issueId"].encode("utf-8").hex() or "empty"
        safe_key=f"{item['origin']}-idhex-{encoded}-occurrence-{item['sourceOccurrence']:06d}"
        expected_key=item["issueId"] if valid_id and id_counts[item["issueId"]]==1 else safe_key
        if item["queueKey"]!=expected_key: errors.append(f"non-injective or non-canonical queue key: {item['queueKey']}")
        if item["origin"]=="stage3":
            candidate=candidates.get(item["sourceCandidateId"])
            if candidate is None:
                errors.append(f"Stage 3 item is not bound to a sweep candidate: {item['queueKey']} (no candidate {item['sourceCandidateId']!r})")
            elif hashlib.sha256(canonical(candidate)).hexdigest()!=item["sourceCandidateDigest"]:
                errors.append(f"Stage 3 item is not bound to a sweep candidate: {item['queueKey']} (recorded {item['sourceCandidateDigest']}, recomputed {hashlib.sha256(canonical(candidate)).hexdigest()})")
            elif item["blindedRecord"]!=candidate_issue_record(candidate):
                errors.append(f"Stage 3 item substance does not match sweep candidate: {item['queueKey']}")
        elif item["sourceCandidateId"] is not None or item["sourceCandidateDigest"] is not None:
            errors.append(f"non-Stage 3 item has sweep provenance: {item['queueKey']}")
    for item in items:
        recomputed=hashlib.sha256(canonical(item["blindedRecord"])).hexdigest()
        if recomputed!=item["issueRecordDigest"]: errors.append(f"issueRecordDigest mismatch: {item['queueKey']} (recorded {item['issueRecordDigest']}, recomputed {recomputed})")
    entries=ledger["entries"]
    if [x["queueKey"] for x in entries]!=keys: errors.append("ledger entries do not exactly match index order")
    for entry in entries:
        for attempt in entry.get("attempts",[]):
            expected_files.update(p for p in (attempt.get("requestPath"),attempt.get("resultPath")) if p)
        if entry.get("acceptedResult"): expected_files.add(entry["acceptedResult"])
    entry_by_key={x["queueKey"]:x for x in entries}; accepted=inline=terminal=0; accepted_results=[]
    request_schema=load(SCHEMAS/"verifier-request-1.0.json"); result_schema=load(SCHEMAS/"verifier-result-1.0.json")
    for item in items:
        entry=entry_by_key.get(item["queueKey"])
        if not entry: continue
        state=entry["state"]; attempts=entry["attempts"]
        allowed_transitions={"pending":{"attempt-1-invoked"},"attempt-1-invoked":{"attempt-1-rejected","accepted","terminal"},"attempt-1-rejected":{"attempt-2-invoked","inline","terminal"},"attempt-2-invoked":{"accepted","inline","terminal"},"accepted":set(),"inline":set(),"terminal":set()}
        previous_state="pending"
        for transition in entry["history"]:
            if transition["from"]!=previous_state or transition["to"] not in allowed_transitions.get(previous_state,set()):
                errors.append(f"invalid ledger transition history: {item['queueKey']}")
                break
            previous_state=transition["to"]
        if previous_state!=state:
            errors.append(f"ledger history does not reach current state: {item['queueKey']}")
        if [a["number"] for a in attempts]!=list(range(1,len(attempts)+1)): errors.append(f"non-contiguous attempts: {item['queueKey']}")
        previous_issue=None
        results_by_attempt={}
        for attempt in attempts:
            request_path=safe(run,attempt["requestPath"],errors,"request")
            if not request_path.is_file(): errors.append(f"request missing: {attempt['requestPath']}"); continue
            if sha(request_path)!=attempt["requestSha256"]: errors.append(f"request digest mismatch: {attempt['requestPath']} (recorded {attempt['requestSha256']}, recomputed {sha(request_path)})")
            request=load(request_path); errors.extend(f"{attempt['requestPath']}: {e}" for e in validate(request,request_schema))
            if (request.get("queueKey"),request.get("issueId"),request.get("origin"),request.get("attempt"),request.get("corpusDigest"),request.get("verificationMode"))!=(item["queueKey"],item["issueId"],item["origin"],attempt["number"],corpus["aggregateDigest"],envelope["verificationMode"]): errors.append(f"request/index identity or mode mismatch: {item['queueKey']} attempt {attempt['number']}")
            if request.get("issueRecord")!=item["blindedRecord"]: errors.append(f"request substance differs from frozen item: {item['queueKey']}")
            for field,declared in (("model",request.get("model")),("effort",request.get("effort"))):
                recorded=attempt.get(field)
                if recorded is not None and declared is not None and recorded!=declared:
                    errors.append(f"ledger {field} differs from its request: {item['queueKey']} attempt {attempt['number']} (request {declared!r}, ledger {recorded!r})")
            # Both delegated attempts run the same fresh verifier role, so both attest it.
            if attempt.get("model") is not None and attempt["model"]!=environment["verifierModel"]:
                errors.append(f"attempt {attempt['number']} model {attempt['model']!r} does not attest manifest verifierModel {environment['verifierModel']!r}: {item['queueKey']}")
            declared_effort=environment.get("reasoningEffort",{}).get("verifier")
            if attempt.get("effort") is not None and declared_effort is not None and attempt["effort"]!=declared_effort:
                errors.append(f"attempt {attempt['number']} effort {attempt['effort']!r} does not attest manifest verifier effort {declared_effort!r}: {item['queueKey']}")
            if previous_issue is not None and request.get("issueRecord")!=previous_issue: errors.append(f"attempt 2 changed issue substance: {item['queueKey']}")
            previous_issue=request.get("issueRecord")
            if attempt["resultPath"] is None:
                invoked_without_result=attempt["outcome"]=="invoked" and attempt["defectCode"] is None and attempt["defect"] is None
                interrupted_without_result=attempt["outcome"]=="rejected" and attempt["defectCode"]=="transient execution" and bool(attempt["defect"])
                if attempt["resultSha256"] is not None or not (invoked_without_result or interrupted_without_result): errors.append(f"missing result has inconsistent state: {item['queueKey']}")
                results_by_attempt[attempt["number"]]=None
                continue
            result_path=safe(run,attempt["resultPath"],errors,"result")
            if not result_path.is_file(): errors.append(f"result missing: {attempt['resultPath']}"); continue
            if sha(result_path)!=attempt["resultSha256"]: errors.append(f"result digest mismatch: {attempt['resultPath']} (recorded {attempt['resultSha256']}, recomputed {sha(result_path)})")
            raw=result_path.read_text(encoding="utf-8", errors="replace")
            try: result=json.loads(raw)
            except json.JSONDecodeError:
                if attempt["outcome"]!="rejected" or attempt["defectCode"]!="malformed result": errors.append(f"unparseable result lacks malformed-result rejection: {attempt['resultPath']}")
                results_by_attempt[attempt["number"]]=None
                continue
            # "schema invalid" covers every check the validators make of a reply: shape, the severity/rubric pair and the
            # exact quotes. Such a reply is rejected and never used, so its errors are expected, not run errors.
            result_errors=validate(result,result_schema)+verifier_result_errors(result)
            if not result_errors: result_errors=validate_quotes(result,docs,corpus_paths)
            if result_errors:
                if attempt["outcome"]!="rejected" or attempt["defectCode"]!="schema invalid": errors.extend(f"{attempt['resultPath']}: {e}" for e in result_errors)
                results_by_attempt[attempt["number"]]=None
                continue
            results_by_attempt[attempt["number"]]=result
            if (result.get("queueKey"),result.get("issueId"),result.get("origin"),result.get("attempt"))!=(item["queueKey"],item["issueId"],item["origin"],attempt["number"]): errors.append(f"result/request identity mismatch: {item['queueKey']}")
        for attempt in attempts:
            result=results_by_attempt.get(attempt["number"])
            if attempt["outcome"] in {"invoked","accepted"} and attempt["defectCode"] is not None: errors.append(f"non-rejected attempt carries defectCode: {item['queueKey']}")
            if attempt["outcome"]=="rejected" and attempt["defectCode"] is None: errors.append(f"rejected attempt lacks defectCode: {item['queueKey']}")
            if result is None: continue
            blocked=result.get("verdict")=="Blocked"; cause=result.get("blockedCause")
            if blocked and attempt["defectCode"]!=cause: errors.append(f"blocked cause and ledger defectCode differ: {item['queueKey']}")
            if attempt["outcome"]=="accepted" and blocked: errors.append(f"blocked verifier result cannot be accepted: {item['queueKey']}")
            if attempt["outcome"]=="rejected" and not blocked: errors.append(f"schema-valid non-blocked result cannot be labelled rejected: {item['queueKey']}")
            if cause=="digest mismatch" and (state!="terminal" or attempt["number"]!=len(attempts)): errors.append(f"digest mismatch must terminate immediately: {item['queueKey']}")
            if cause=="unreadable source" and len(attempts)>attempt["number"]: errors.append(f"unreadable source cannot be redispatched: {item['queueKey']}")
        if len(attempts)==2 and attempts[0]["defectCode"] not in {"malformed result","schema invalid","invalid invocation","transient execution"}:
            errors.append(f"attempt 2 was not eligible under the retry ladder: {item['queueKey']}")
        if state=="pending" and (attempts or entry["acceptedResult"] is not None): errors.append(f"invalid pending state: {item['queueKey']}")
        elif state=="attempt-1-invoked" and not (len(attempts)==1 and attempts[-1]["outcome"]=="invoked"): errors.append(f"invalid attempt-1-invoked state: {item['queueKey']}")
        elif state=="attempt-1-rejected" and not (len(attempts)==1 and attempts[-1]["outcome"]=="rejected"): errors.append(f"invalid attempt-1-rejected state: {item['queueKey']}")
        elif state=="attempt-2-invoked" and not (len(attempts)==2 and attempts[0]["outcome"]=="rejected" and (attempts[1]["outcome"]=="invoked" or (attempts[1]["outcome"]=="rejected" and envelope["verificationFallback"]=="inline"))): errors.append(f"invalid attempt-2-invoked state: {item['queueKey']}")  # a rejected attempt 2 rests here only while the explicit inline fallback is pending
        elif state=="accepted":
            accepted+=1
            if not attempts or attempts[-1]["outcome"]!="accepted" or entry["acceptedResult"]!=attempts[-1]["resultPath"]: errors.append(f"invalid accepted state: {item['queueKey']}")
            elif results_by_attempt.get(attempts[-1]["number"]): accepted_results.append(results_by_attempt[attempts[-1]["number"]])
        elif state=="inline":
            inline+=1
            retryable={"malformed result","schema invalid","invalid invocation","transient execution"}
            first_defect=attempts[0]["defectCode"] if attempts else None
            if not attempts or attempts[-1]["outcome"]!="rejected": errors.append(f"inline fallback requires a rejected delegated result: {item['queueKey']}")
            if first_defect in retryable and len(attempts)<2: errors.append(f"inline fallback skipped required second verifier: {item['queueKey']}")
            if len(attempts)==1 and first_defect!="unreadable source": errors.append(f"attempt-1 defect is not directly eligible for inline fallback: {item['queueKey']}")
            if any(attempt["defectCode"]=="digest mismatch" for attempt in attempts): errors.append(f"digest mismatch forbids inline fallback: {item['queueKey']}")
            if entry.get("inlineModel") is not None and entry["inlineModel"]!=environment["coordinatorModel"]:
                errors.append(f"inline fallback runs in the coordinator context but records {entry['inlineModel']!r} against coordinatorModel {environment['coordinatorModel']!r}: {item['queueKey']}")
            declared_inline_effort=environment.get("reasoningEffort",{}).get("coordinator")
            if entry.get("inlineEffort") is not None and declared_inline_effort is not None and entry["inlineEffort"]!=declared_inline_effort:
                errors.append(f"inline fallback effort {entry['inlineEffort']!r} does not attest manifest coordinator effort {declared_inline_effort!r}: {item['queueKey']}")
            if dispatch["mode"]=="subagent" and f"verifier/{item['queueKey']}/inline" not in unit_ids: errors.append(f"inline fallback verification lacks its dispatch record verifier/{item['queueKey']}/inline: {item['queueKey']}")
            if envelope["verificationFallback"]!="inline" or not entry["acceptedResult"] or not entry["inlineResultSha256"]: errors.append(f"invalid inline state: {item['queueKey']}")
            else:
                inline_path=safe(run,entry["acceptedResult"],errors,"inline result")
                if not inline_path.is_file(): errors.append(f"inline result missing: {item['queueKey']}")
                else:
                    if sha(inline_path)!=entry["inlineResultSha256"]: errors.append(f"inline result digest mismatch: {item['queueKey']} (recorded {entry['inlineResultSha256']}, recomputed {sha(inline_path)})")
                    inline_result=load(inline_path); inline_errors=validate(inline_result,result_schema)+verifier_result_errors(inline_result); errors.extend(f"{entry['acceptedResult']}: {e}" for e in inline_errors); errors.extend(f"{entry['acceptedResult']}: {e}" for e in validate_quotes(inline_result,docs,corpus_paths))
                    if not inline_errors: accepted_results.append(inline_result)
                    if (inline_result.get("queueKey"),inline_result.get("issueId"),inline_result.get("origin"),inline_result.get("attempt"))!=(item["queueKey"],item["issueId"],item["origin"],"inline"): errors.append(f"inline result identity mismatch: {item['queueKey']}")
        elif state=="terminal":
            terminal+=1
            retryable={"malformed result","schema invalid","invalid invocation","transient execution"}
            if not attempts or attempts[-1]["outcome"]!="rejected": errors.append(f"terminal state requires a rejected final attempt: {item['queueKey']}")
            elif len(attempts)==1:
                defect=attempts[0]["defectCode"]
                if defect in retryable: errors.append(f"terminal state skipped required second verifier: {item['queueKey']}")
                elif defect not in {"unreadable source","digest mismatch"}: errors.append(f"attempt-1 defect is not terminal-eligible: {item['queueKey']}")
            if entry["acceptedResult"] is not None: errors.append(f"terminal state cannot carry an accepted result: {item['queueKey']}")
        if state!="inline" and entry["inlineResultSha256"] is not None: errors.append(f"non-inline state carries inline digest: {item['queueKey']}")
        if state!="inline" and (entry.get("inlineModel") is not None or entry.get("inlineEffort") is not None): errors.append(f"non-inline state carries inline model provenance: {item['queueKey']}")
    summary=manifest["stage3Ledger"]
    if summary is None or summary["path"]!="stage-3/verification-ledger.json" or summary["sha256"]!=sha(ledger_path) or (summary["accepted"],summary["inline"],summary["terminal"])!=(accepted,inline,terminal):
        recorded=(summary or {}).get("sha256"); counts=((summary or {}).get("accepted"),(summary or {}).get("inline"),(summary or {}).get("terminal"))
        errors.append(f"manifest ledger summary does not reconcile (recorded sha256 {recorded}, recomputed {sha(ledger_path)}; recorded counts {counts}, recomputed {(accepted,inline,terminal)})")
    if manifest["status"]=="completed":
        if any(manifest["stages"][s]["state"]!="accepted" for s in ("stage1","stage2","stage3")): errors.append("completed run has non-accepted stage")
        if terminal or accepted+inline!=n or "final-review.md" not in artifact_paths: errors.append("completed run has unreconciled queue or no final report")
        if "final-review.md" in artifact_paths:
            expected_calibration={stage:{category:0 for category in ("confirmed","corrected","false positive","unverifiable","blocked")} for stage in ("Stage 1","Stage 2","Stage 3")}
            origin_names={"stage1":"Stage 1","stage2":"Stage 2","stage3":"Stage 3"}; verdict_columns={"Confirmed":"confirmed","Partially confirmed":"corrected","False positive":"false positive","Unverifiable":"unverifiable","Blocked":"blocked"}
            for result in accepted_results: expected_calibration[origin_names[result["origin"]]][verdict_columns[result["verdict"]]]+=1
            observed_calibration=None
            tables,_=parse_tables(artifact_paths["final-review.md"].read_text(encoding="utf-8").splitlines())
            for heading,header,rows in tables:
                normalized=[cell.lower() for cell in header]
                if "per-stage correction" in heading.lower() and normalized==["stage","confirmed","corrected","false positive","unverifiable","blocked"]:
                    observed_calibration={}
                    for row in rows:
                        try: observed_calibration[row[0]]={column:int(value) for column,value in zip(normalized[1:],row[1:])}
                        except ValueError: errors.append("final calibration table contains non-integer counts")
            if observed_calibration!=expected_calibration: errors.append(f"final calibration cells do not reconcile: expected {expected_calibration}, got {observed_calibration}")
    return finish(errors+stray_errors(run,expected_files,corpus_prefix(envelope),open_replies(manifest,run,ledger)))

def finish(errors:list[str])->int:
    if errors:
        for error in errors: print("ERROR: "+error,file=sys.stderr)
        return 1
    print("run artifacts and protocol invariants reconcile")
    return 0
if __name__=="__main__": raise SystemExit(main())
