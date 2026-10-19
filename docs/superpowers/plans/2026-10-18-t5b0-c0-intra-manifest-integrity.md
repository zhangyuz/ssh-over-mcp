# C0 Intra-manifest Object Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task (RED then GREEN).

**Goal:** Refuse ambiguous URLs and SHA-256 size claims inside one offline C0 manifest via all existing review entrypoints.
**Architecture:** Minimal bounded validation in validate(doc), reuse existing report/refusal mapping.
**Tech Stack:** Python stdlib 3.13/3.14, unittest, hosted pytest bridge.
**Spec:** docs/superpowers/specs/2026-10-18-t5b0-c0-intra-manifest-integrity-design.md

## Global Constraints
- Four objects per manifest; 16 input manifests; 16 KiB/record; 64 directory entries.
- No raw URL or digest in errors; NO_AUTHORIZATION/C0_COLLECT_HOLD/NO_NETWORK immutable.
- No material collection or privilege; preserve all existing legacy output shapes.

## Review Focus
- URL reused by different IDs must refuse, even with identical metadata.
- Same SHA-256 declared with different bytes must refuse.
- Distinct URLs, same SHA-256 and bytes may pass.
- Invalid fields/types must retain INVALID_STRUCTURE classification.
- Aggregate refusal must prevent any semantic object diff.

---

### Task 1: Reproduce inconsistency with executable RED fixtures
**Files:** ops/t5b0/test_c0_manifest_preflight.py
**Interfaces:** Existing validate(doc), inspect_manifest, directory_report, existing CLI.
- [ ] Add collision fixtures and safe mirror control.
- [ ] Assert error classification, no URL/digest echo, and refusal across existing entrypoints.
- [ ] Run focused tests against original code; confirm expected conflict assertions FAIL.
- [ ] Commit RED tests.

### Task 2: Minimal fix and user-facing evidence
**Files:** ops/t5b0/c0_manifest_preflight.py, docs/evidence/2026-10-17-adr19-t5b0-c0-offline-structure-preflight.md, docs/development-plan.md.
**Interfaces:** validate(doc) returns list[str], no new API.
- [ ] Add per-manifest URL uniqueness and digest-size consistency checks.
- [ ] Re-run focused tests GREEN, all C0 offline tests and hosted pytest bridge.
- [ ] Update runbook/roadmap and progress handoff with exact evidence.
- [ ] Ruff, compile, diff check; commit and push.
- [ ] Await exact HEAD CI and independent review before Ready/merge; never self-authorize admission.
