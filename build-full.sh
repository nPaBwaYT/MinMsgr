#!/bin/bash

# MinMessenger Full Build Script (Bash)
# Builds WASM, client, and Docker images

set -e

# Parse flags
SKIP_WASM=false
SKIP_CLIENT=false
SKIP_DOCKER=false

for arg in "$@"; do
    case $arg in
        --skip-wasm)
            SKIP_WASM=true
            shift
            ;;
        --skip-client)
            SKIP_CLIENT=true
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: ./build-full.sh [--skip-wasm] [--skip-client] [--skip-docker]"
            exit 1
            ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

function write_status() {
    echo ""
    echo -e "${CYAN}========================================"
    echo -e "$1"
    echo -e "========================================${NC}"
    echo ""
}

function write_error_exit() {
    echo ""
    echo -e "${RED}❌ ERROR: $1${NC}"
    echo ""
    exit 1
}

write_status "MinMessenger Full Build"

# ============================================================
# Step 1: Build WASM Module
# ============================================================
if [ "$SKIP_WASM" = false ]; then
    write_status "${YELLOW}Step 1/4: Building WASM Encryption Module${NC}"
    
    echo -e "${GRAY}Creating output directory...${NC}"
    mkdir -p client/public
    
    echo -e "${GRAY}Setting Go environment variables...${NC}"
    export GOOS=js
    export GOARCH=wasm
    export CGO_ENABLED=0
    
    echo -e "${GRAY}Compiling WASM module...${NC}"
    cd server
    if ! go build -o ../client/public/crypto.wasm ./cmd/wasm; then
        cd ..
        write_error_exit "WASM build failed"
    fi
    cd ..
    
    # Verify WASM file
    if [ ! -f "client/public/crypto.wasm" ]; then
        write_error_exit "WASM file not created at client/public/crypto.wasm"
    fi
    
    WASM_SIZE=$(stat -f%z "client/public/crypto.wasm" 2>/dev/null || stat -c%s "client/public/crypto.wasm" 2>/dev/null)
    WASM_MAGIC=$(xxd -p -l 4 "client/public/crypto.wasm" 2>/dev/null || head -c 4 "client/public/crypto.wasm" | xxd -p)
    
    if [ "$WASM_MAGIC" = "0061736d" ] || [ "$WASM_MAGIC" = "00 61 73 6d" ]; then
        echo -e "${GREEN}✅ WASM module built successfully${NC}"
        echo -e "${GRAY}   File: client/public/crypto.wasm${NC}"
        echo -e "${GRAY}   Size: $WASM_SIZE bytes${NC}"
        echo -e "${GRAY}   Magic: $WASM_MAGIC (valid WebAssembly)${NC}"
    else
        write_error_exit "Invalid WASM magic number: $WASM_MAGIC (expected 0061736d). File may be corrupted."
    fi
else
    echo -e "${YELLOW}⏭️  Skipping WASM build (--skip-wasm flag set)${NC}"
fi

# ============================================================
# Step 2: Install Client Dependencies
# ============================================================
if [ "$SKIP_CLIENT" = false ]; then
    write_status "${YELLOW}Step 2/4: Installing Client Dependencies${NC}"
    
    cd client
    echo -e "${GRAY}Running npm install...${NC}"
    if ! npm install; then
        cd ..
        write_error_exit "npm install failed"
    fi
    echo -e "${GREEN}✅ Client dependencies installed${NC}"
    
    # ============================================================
    # Step 3: Build Client (Production Build)
    # ============================================================
    write_status "${YELLOW}Step 3/4: Building Client Application${NC}"
    
    echo -e "${GRAY}Running npm run build...${NC}"
    if ! npm run build; then
        cd ..
        write_error_exit "npm run build failed"
    fi
    
    if [ ! -d "dist" ]; then
        cd ..
        write_error_exit "Build succeeded but dist folder not found"
    fi
    echo -e "${GREEN}✅ Client build completed${NC}"
    echo -e "${GRAY}   Output: dist/${NC}"
    
    cd ..
else
    echo -e "${YELLOW}⏭️  Skipping client build (--skip-client flag set)${NC}"
fi

# ============================================================
# Step 4: Build Docker Images
# ============================================================
if [ "$SKIP_DOCKER" = false ]; then
    write_status "${YELLOW}Step 4/4: Building Docker Images${NC}"
    
    DOCKERFILES=("Dockerfile.gateway" "Dockerfile.auth" "Dockerfile.chat" "Dockerfile.message" "Dockerfile.contact")
    IMAGE_NAMES=("minmsgr-gateway" "minmsgr-auth" "minmsgr-chat" "minmsgr-message" "minmsgr-contact")
    
    DOCKERFILE_COUNT=0
    for i in "${!DOCKERFILES[@]}"; do
        DOCKERFILE="${DOCKERFILES[$i]}"
        IMAGE_NAME="${IMAGE_NAMES[$i]}"
        
        if [ -f "$DOCKERFILE" ]; then
            echo -e "${GRAY}Building $IMAGE_NAME...${NC}"
            if ! docker build -f "$DOCKERFILE" -t "minmsgr/$IMAGE_NAME:latest" .; then
                write_error_exit "Docker build failed for $IMAGE_NAME"
            fi
            echo -e "${GREEN}✅ $IMAGE_NAME${NC}"
            ((DOCKERFILE_COUNT++))
        fi
    done
    
    if [ $DOCKERFILE_COUNT -eq 0 ]; then
        echo -e "${YELLOW}⚠️  No Dockerfile found${NC}"
    else
        echo ""
        echo -e "${GREEN}✅ Built $DOCKERFILE_COUNT Docker image(s)${NC}"
    fi
else
    echo -e "${YELLOW}⏭️  Skipping Docker build (--skip-docker flag set)${NC}"
fi

# ============================================================
# Summary
# ============================================================
write_status "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}✅ All build steps completed successfully!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Start services:"
echo "   - PostgreSQL and Kafka (or use: docker-compose up -d)"
echo "2. Run server:"
echo "   - ./server/gateway"
echo "3. Start client (dev mode):"
echo "   - cd client && npm run dev"
echo "4. Open browser:"
echo "   - http://localhost:5173"
echo ""
echo -e "${CYAN}For production Docker deployment:${NC}"
echo "  docker-compose build && docker-compose up -d"
echo ""
echo -e "${GRAY}Build flags:${NC}"
echo "  --skip-wasm    Skip WASM compilation"
echo "  --skip-client  Skip npm install/build"
echo "  --skip-docker  Skip Docker image builds"
echo ""
