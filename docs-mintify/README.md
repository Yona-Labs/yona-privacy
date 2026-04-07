# Yona Documentation

This directory contains the documentation for Yona - a privacy-preserving protocol on Solana, built with [Mintlify](https://mintlify.com).

## Overview

Yona enables private trustless DeFi on Solana. Shield SOL and any SPL token into a privacy pool and trade any pair privately on Jupiter using zero-knowledge proofs.

Key capabilities:
- Private deposits and withdrawals
- Anonymous token swaps via Jupiter
- Zero-knowledge proof verification on-chain
- No trusted parties, only ZK cryptography

## Documentation Structure

```
docs-mintify/
├── index.mdx                    # Home page
├── quickstart.mdx               # Quick start guide
├── concepts/                    # Core concepts
│   ├── technical.mdx           # Technical overview
│   ├── fees.mdx                # Fee structure
│   ├── relayer.mdx             # Relayer network
│   ├── indexer.mdx             # Indexer service
│   ├── how-it-works.mdx        # How privacy works
│   └── privacy.mdx             # Privacy model
└── features/                    # Feature documentation
    ├── deposit.mdx             # Deposit guide
    ├── withdraw.mdx            # Withdrawal guide
    ├── swap.mdx                # Swap guide
    └── bridge.mdx              # Bridge guide
```

## Development

Install the [Mintlify CLI](https://www.npmjs.com/package/mintlify) to preview the documentation locally:

```bash
npm i -g mintlify
```

Run the development server:

```bash
cd docs-mintify
mintlify dev
```

The documentation will be available at `http://localhost:3000`.

## Publishing

Changes are automatically deployed when pushed to the main branch. Before pushing:

1. Test locally with `mintlify dev`
2. Check all links work
3. Verify code examples
4. Review formatting and content

## Documentation Principles

### User-Focused
- Clear, non-technical explanations
- Step-by-step guides with examples
- Privacy best practices
- Visual aids where helpful

### Comprehensive
- Quick start for new users
- Detailed feature documentation
- Technical concepts explained
- Security and privacy information

### Well-Organized
- Logical navigation structure
- Cross-references between pages
- Progressive disclosure of complexity
- Search-optimized content

## Contributing

To improve the documentation:

1. Edit the relevant `.mdx` files
2. Test locally with `mintlify dev`
3. Ensure all links and formatting work
4. Submit a pull request

## Links

- **GitHub**: https://github.com/Yona-Labs/yona-privacy-app
- **Twitter**: https://x.com/YonaPrivacy
- **Discord**: https://discord.gg/yona-labs
- **Mintlify Docs**: https://mintlify.com/docs

## License

See [LICENSE](./LICENSE) file for details.
