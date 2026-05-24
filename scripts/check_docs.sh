#!/usr/bin/env bash
set -euo pipefail

echo "==> Checking for Quarto..."
if ! command -v quarto &>/dev/null; then
	echo "⚠️  Quarto CLI is not installed."
	echo "💡 Skipping documentation build and Mermaid validation."
	echo "   To install Quarto, visit: https://quarto.org/docs/get-started/"
	exit 0
fi

echo "==> Rendering Quarto documentation..."

quarto render docs/

echo "==> Validating Mermaid diagrams..."

# -r (recursive), -l (files-with-matches: only print the filename)
# We append `|| true` so that if grep finds NOTHING (exit code 1),
# `set -e` doesn't instantly kill the script.
FAILING_FILES=$(grep -rlE --include="*.html" "Syntax error in (text|graph)" "docs/_book/" || true)

if [[ -n "$FAILING_FILES" ]]; then
	echo -e "\n❌ FATAL: Broken Mermaid diagram detected in the generated output."
	echo "Please check the following source files:"

	for file in $FAILING_FILES; do
		# Convert the generated tmp path back to the real source file
		# e.g., /tmp/tmp.XXXX/_book/symbolizer.html -> symbolizer -> docs/symbolizer.qmd
		BASENAME=$(basename "$file" .html)
		echo "  👉 docs/${BASENAME}.qmd"
	done

	exit 1
fi

echo "✅ All diagrams compiled successfully."
