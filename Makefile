# GoMesh developer tasks. Run `make help` for the list.

GOBIN        := $(shell go env GOPATH)/bin
GOMOBILE     := $(GOBIN)/gomobile
APPLE        := apps/apple
XCFRAMEWORK  := $(APPLE)/Frameworks/GoMeshCore.xcframework
DERIVED      := $(APPLE)/DerivedData
SIM          ?= iPhone 16 Pro

.PHONY: help test server server-linux tui dev-cert xcframework xcodeproj app-mac app-sim tools

help:
	@echo "make test          run every Go test suite"
	@echo "make server        run the server (TLS, see dev-cert)"
	@echo "make server-linux  build the server for Linux (arm64 and amd64) into dist/"
	@echo "make tui           run the terminal client"
	@echo "make dev-cert      create a self-signed TLS cert in server/dev-certs"
	@echo "make xcframework   build the Go engine for iOS, the simulator and macOS"
	@echo "make xcodeproj     generate apps/apple/GoMesh.xcodeproj"
	@echo "make app-mac       build and open the macOS app"
	@echo "make app-sim       build and run the app in the iOS simulator (SIM=\"$(SIM)\")"
	@echo "make tools         install gomobile and xcodegen"

test:
	cd common && go test ./...
	cd server && go test ./...
	cd core && go test ./...
	cd client && go vet ./...
	cd bridge && go test ./...

server:
	cd server && go run .

# The SQLite driver is pure Go, so the server cross-compiles with cgo off.
# See docs/deploy-ec2.md.
server-linux:
	cd server && for arch in arm64 amd64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags="-s -w" \
			-o ../dist/gomesh-server-linux-$$arch . || exit 1; \
	done
	@ls -l dist/gomesh-server-linux-*

tui:
	cd client && go run .

dev-cert:
	cd server && go run . -gen-dev-cert dev-certs

tools:
	go install golang.org/x/mobile/cmd/gomobile@latest
	go install golang.org/x/mobile/cmd/gobind@latest
	brew list xcodegen >/dev/null 2>&1 || brew install xcodegen

# MACOSX_DEPLOYMENT_TARGET keeps the cgo objects at the app's minimum macOS
# version instead of the build machine's. The build cache does not key on it,
# so -a rebuilds everything rather than reuse objects compiled without it.
xcframework:
	cd bridge && PATH="$(GOBIN):$$PATH" MACOSX_DEPLOYMENT_TARGET=14.0 \
		$(GOMOBILE) bind -a -target=ios,iossimulator,macos -iosversion=17.0 \
		-o ../$(XCFRAMEWORK) .

xcodeproj:
	cd $(APPLE) && xcodegen generate

app-mac: xcframework xcodeproj
	xcodebuild -project $(APPLE)/GoMesh.xcodeproj -scheme GoMesh \
		-destination 'platform=macOS' -derivedDataPath $(DERIVED) build
	open $(DERIVED)/Build/Products/Debug/GoMesh.app

app-sim: xcframework xcodeproj
	xcodebuild -project $(APPLE)/GoMesh.xcodeproj -scheme GoMesh \
		-destination 'platform=iOS Simulator,name=$(SIM)' -derivedDataPath $(DERIVED) build
	xcrun simctl boot "$(SIM)" 2>/dev/null || true
	open -a Simulator
	xcrun simctl install "$(SIM)" $(DERIVED)/Build/Products/Debug-iphonesimulator/GoMesh.app
	xcrun simctl launch "$(SIM)" com.mehulraj.gomesh
