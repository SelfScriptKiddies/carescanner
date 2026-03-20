VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
NAME    := carescanner
DIST    := dist

# Targets
LINUX_AMD64   := x86_64-unknown-linux-musl
LINUX_ARM64   := aarch64-unknown-linux-musl
WINDOWS_AMD64 := x86_64-pc-windows-gnu
MACOS_AMD64   := x86_64-apple-darwin
MACOS_ARM64   := aarch64-apple-darwin

.PHONY: all clean linux linux-amd64 linux-arm64 windows macos release install help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Individual targets ---

linux-amd64: ## Build static Linux x86_64 binary (musl)
	cross build --release --target $(LINUX_AMD64)
	@mkdir -p $(DIST)
	cp target/$(LINUX_AMD64)/release/$(NAME) $(DIST)/$(NAME)-$(VERSION)-linux-amd64
	@echo "Built: $(DIST)/$(NAME)-$(VERSION)-linux-amd64"

linux-arm64: ## Build static Linux aarch64 binary (musl)
	cross build --release --target $(LINUX_ARM64)
	@mkdir -p $(DIST)
	cp target/$(LINUX_ARM64)/release/$(NAME) $(DIST)/$(NAME)-$(VERSION)-linux-arm64
	@echo "Built: $(DIST)/$(NAME)-$(VERSION)-linux-arm64"

windows: ## Build Windows x86_64 binary (.exe)
	cross build --release --target $(WINDOWS_AMD64)
	@mkdir -p $(DIST)
	cp target/$(WINDOWS_AMD64)/release/$(NAME).exe $(DIST)/$(NAME)-$(VERSION)-windows-amd64.exe
	@echo "Built: $(DIST)/$(NAME)-$(VERSION)-windows-amd64.exe"

macos-amd64: ## Build macOS x86_64 binary (requires macOS or cross)
	cargo build --release --target $(MACOS_AMD64)
	@mkdir -p $(DIST)
	cp target/$(MACOS_AMD64)/release/$(NAME) $(DIST)/$(NAME)-$(VERSION)-macos-amd64
	@echo "Built: $(DIST)/$(NAME)-$(VERSION)-macos-amd64"

macos-arm64: ## Build macOS aarch64 binary (requires macOS or cross)
	cargo build --release --target $(MACOS_ARM64)
	@mkdir -p $(DIST)
	cp target/$(MACOS_ARM64)/release/$(NAME) $(DIST)/$(NAME)-$(VERSION)-macos-arm64
	@echo "Built: $(DIST)/$(NAME)-$(VERSION)-macos-arm64"

# --- Convenience groups ---

linux: linux-amd64 linux-arm64 ## Build all Linux targets

macos: macos-amd64 macos-arm64 ## Build all macOS targets

all: linux windows ## Build Linux + Windows (cross-compilable from Linux)

release: all ## Build all + create archives
	@cd $(DIST) && for f in $(NAME)-$(VERSION)-*; do \
		case "$$f" in \
			*.exe) zip "$${f%.exe}.zip" "$$f" ;; \
			*.tar.gz|*.zip) ;; \
			*) tar czf "$$f.tar.gz" "$$f" ;; \
		esac; \
	done
	@echo "\nRelease artifacts in $(DIST)/:"
	@ls -lh $(DIST)/*.tar.gz $(DIST)/*.zip 2>/dev/null

# --- Dev targets ---

build: ## Build for current platform (dev)
	cargo build --release

install: build ## Install to ~/.cargo/bin
	cargo install --path .

checksums: ## Generate SHA256 checksums for dist/
	@cd $(DIST) && sha256sum $(NAME)-$(VERSION)-*.tar.gz $(NAME)-$(VERSION)-*.zip 2>/dev/null > SHA256SUMS
	@echo "Checksums written to $(DIST)/SHA256SUMS"
	@cat $(DIST)/SHA256SUMS

clean: ## Remove build artifacts
	cargo clean
	rm -rf $(DIST)

# --- Setup (install cross-compilation tools) ---

setup-cross: ## Install 'cross' and required targets
	cargo install cross --git https://github.com/cross-rs/cross
	@echo "cross installed. Requires Docker or Podman for cross-compilation."
	@echo "Run: make all"
