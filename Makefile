BINARY := exex
# Strip the symbol table (-s) and DWARF (-w) from release builds.
LDFLAGS := -s -w
DIST := dist
VERSION ?= dev
# Platforms built by `make release`.
RELEASE_PLATFORMS ?= darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/386 linux/arm
# Man page and its install location (override with `make install-man MANPREFIX=...`).
MANPAGE := docs/exex.1
MANPREFIX ?= /usr/local/share/man
# Shell-completion install dirs (override per platform, e.g. with brew --prefix).
BASHCOMPDIR ?= /usr/local/etc/bash_completion.d
ZSHCOMPDIR ?= /usr/local/share/zsh/site-functions
FISHCOMPDIR ?= /usr/local/share/fish/vendor_completions.d

.PHONY: build lite install install-man install-completions test test-cross lint-docs size-report perf-report clean release

# Full build: includes Chroma syntax highlighting (source pane + asm colours).
build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

# Lite build: drops Chroma (and its embedded lexer/style data), ~3.5 MB smaller.
# Syntax highlighting falls back to the built-in minimal highlighter.
lite:
	go build -tags lite -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

install:
	go install -trimpath -ldflags="$(LDFLAGS)" .

# Install the man page into $(MANPREFIX)/man1 (use sudo for a system prefix).
install-man:
	install -d "$(MANPREFIX)/man1"
	install -m 0644 "$(MANPAGE)" "$(MANPREFIX)/man1/exex.1"

# Install shell completions (override *COMPDIR vars for your platform).
install-completions:
	install -d "$(BASHCOMPDIR)" "$(ZSHCOMPDIR)" "$(FISHCOMPDIR)"
	install -m 0644 completions/exex.bash "$(BASHCOMPDIR)/exex"
	install -m 0644 completions/_exex "$(ZSHCOMPDIR)/_exex"
	install -m 0644 completions/exex.fish "$(FISHCOMPDIR)/exex.fish"

test:
	go test ./...
	go vet -tags lite ./...

# Lint the man page with mandoc. STYLE-level notes are not fatal; WARNING and
# ERROR are (so malformed roff fails the build). mandoc ships with macOS/BSD and is
# `apt-get install mandoc` on Debian/Ubuntu.
lint-docs:
	@command -v mandoc >/dev/null 2>&1 || { echo "mandoc not found (brew install mandoc / apt-get install mandoc)"; exit 1; }
	mandoc -T lint -W warning $(MANPAGE)

# Break down what makes up the binary: stripped full-vs-lite totals (the Chroma
# cost is their difference, since its embedded lexer XML hides under go:string.*),
# then a per-module attribution from the symbol table. See scripts/size-report.sh.
size-report:
	@sh scripts/size-report.sh $(BINARY)

# Performance report: parse/startup cost, every -o view's render time and
# allocation volume, and peak resident memory, measured against a sample binary
# (default: exex itself — a realistic native object that is always present).
# Override the target with SAMPLE=... ; appends to $GITHUB_STEP_SUMMARY in CI.
perf-report: build
	@go run ./tools/perfreport $(if $(SAMPLE),$(SAMPLE),./$(BINARY))

# Slow, toolchain-dependent end-to-end test: cross-compile a tiny program with Go
# and Zig for every target exex can read, then parse/disassemble each. Needs the
# `go` and (for the Zig half) `zig` toolchains; missing targets are skipped.
test-cross:
	go test -tags crosscompile ./internal/integration/ -v

clean:
	rm -f $(BINARY)
	rm -rf $(DIST)

# release cross-compiles full + lite archives for every RELEASE_PLATFORMS entry
# into $(DIST), plus a checksums file. Used by the GitHub release workflow:
#   make release VERSION=v1.2.3
release:
	rm -rf $(DIST) && mkdir -p $(DIST)
	@for platform in $(RELEASE_PLATFORMS); do \
	  os=$${platform%/*}; arch=$${platform#*/}; \
	  for variant in full lite; do \
	    tags=""; suffix=""; \
	    if [ "$$variant" = lite ]; then tags="-tags lite"; suffix="-lite"; fi; \
	    bin=$(BINARY); [ "$$os" = windows ] && bin=$(BINARY).exe; \
	    stage=$$(mktemp -d); \
	    cp docs/config.example.yaml README.md LICENSE $(MANPAGE) "$$stage/" 2>/dev/null || true; \
	    cp -r completions "$$stage/" 2>/dev/null || true; \
	    echo "building $$os/$$arch ($$variant)"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	      go build $$tags -trimpath -ldflags="$(LDFLAGS)" -o "$$stage/$$bin" . || exit 1; \
	    name=$(BINARY)-$(VERSION)-$$os-$$arch$$suffix; \
		tar -czf "$(DIST)/$$name.tar.gz" -C "$$stage" .; \
	    rm -rf "$$stage"; \
	  done; \
	done
	cd $(DIST) && { command -v sha256sum >/dev/null 2>&1 && sha256sum * || shasum -a 256 *; } > checksums.txt
	@ls -lh $(DIST)
