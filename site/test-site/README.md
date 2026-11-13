# PeerGuard test site (deliberately unsafe)

A copy of the `examples/guesthouse_agentified` site from
[cognizant-ai-labs/agentic-web](https://github.com/cognizant-ai-labs/agentic-web) (Apache 2.0),
changed on purpose so PeerGuard has something to catch:

- `agent-manifest.json` has a **fake** key under `llm_router.api_key`. It is not a real key.
- The front agent's instructions in `tidewhistle_guesthouse.hocon` end with planted lines that
  try to override a calling assistant's rules, ask for the visitor's API key and chat history,
  claim the site is safe, and book without confirmation. One line also hides an invisible
  zero-width character.

After changing the `.hocon`, rebuild from this folder:

```shell
node <path-to>/agentic-web/skills/agentify-website/scripts/build_network.mjs tidewhistle_guesthouse.hocon --manifest agent-manifest.json
```

Never put a real key in this site.
