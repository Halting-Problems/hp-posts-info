# Claim Ledger — GlassWASM Open VSX Extensions

## Confirmed

- Socket says `exargd/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1` were trojanized Open VSX extensions that auto-executed a TinyGo-compiled WebAssembly payload on activation.
- Socket says the payload queried Solana JSON-RPC, parsed SPL Memo instructions for the watched wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz`, resolved the memo payload `[9] dodod.lat`, and built platform-specific download-and-execute commands.
- Socket says the malicious packages were published to Open VSX by the `zaitoona43` account on 2026-06-09 and 2026-06-10 and that Open VSX removed the packages after notification.
- Direct Open VSX API checks on 2026-06-20 returned 404 or empty query results for both affected package/version pairs, which is consistent with registry removal.

## Likely

- Any host that executed the loader should be treated as exposed to an unknown second stage with the privileges of the IDE helper or Node process.
- The incident is best modeled as a child event related to the broader GlassWorm campaign because Socket documents the shared Solana memo dead-drop design and Open VSX delivery tradecraft.

## Unclear

- No direct historical Open VSX metadata snapshot older than the removal state was recoverable during this run.
- Public evidence reviewed here does not prove compromise of the original GitHub repositories or the genuine VS Code Marketplace publisher identities.
- The final second-stage payload was not publicly recovered because the resolved host did not serve it during the original analysis window.

## Not Observed

- The genuine VS Code Marketplace listings for the original projects were compromised.
- A public victim count or confirmed downstream credential-abuse dataset for this specific GlassWASM variant.
