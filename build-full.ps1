# MinMessenger Full Build Script (PowerShell)
# Builds WASM, client, and Docker images

param(
    [switch]$SkipWasm = $false,
    [switch]$SkipClient = $false,
    [switch]$SkipDocker = $false
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host "========================================" -ForegroundColor $Color
    Write-Host $Message -ForegroundColor $Color
    Write-Host "========================================" -ForegroundColor $Color
    Write-Host ""
}

function Write-Error-Exit {
    param([string]$Message)
    Write-Host ""
    Write-Host "❌ ERROR: $Message" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Status "MinMessenger Full Build" "Cyan"

# ============================================================
# Step 1: Build WASM Module
# ============================================================
if (-not $SkipWasm) {
    Write-Status "Step 1/4: Building WASM Encryption Module" "Yellow"
    
    Write-Host "Creating output directory..." -ForegroundColor Gray
    New-Item -ItemType Directory -Force -Path "client\public" | Out-Null
    
    Write-Host "Setting Go environment variables..." -ForegroundColor Gray
    $env:GOOS = 'js'
    $env:GOARCH = 'wasm'
    $env:CGO_ENABLED = '0'
    
    Write-Host "Compiling WASM module..." -ForegroundColor Gray
    Push-Location server
    try {
        $output = go build -o ..\client\public\crypto.wasm ./cmd/wasm 2>&1
        if ($LASTEXITCODE -ne 0) {
            Pop-Location
            Write-Error-Exit "WASM build failed: $output"
        }
    } finally {
        Pop-Location
    }
    
    # Verify WASM file
    $wasmPath = "client\public\crypto.wasm"
    if (-not (Test-Path $wasmPath)) {
        Write-Error-Exit "WASM file not created at $wasmPath"
    }
    
    $wasmSize = (Get-Item $wasmPath).Length
    $wasmBytes = [System.IO.File]::ReadAllBytes($wasmPath)
    $firstFour = $wasmBytes[0..3]
    $magicHex = [System.BitConverter]::ToString($firstFour)
    
    if ($magicHex -eq "00-61-73-6D") {
        Write-Host "✅ WASM module built successfully" -ForegroundColor Green
        Write-Host "   File: $wasmPath" -ForegroundColor Gray
        Write-Host "   Size: $wasmSize bytes" -ForegroundColor Gray
        Write-Host "   Magic: $magicHex (valid WebAssembly)" -ForegroundColor Gray
    } else {
        Write-Error-Exit "Invalid WASM magic number: $magicHex (expected 00-61-73-6D). File may be corrupted."
    }
} else {
    Write-Host "⏭️  Skipping WASM build (--SkipWasm flag set)" -ForegroundColor Yellow
}

# ============================================================
# Step 2: Install Client Dependencies
# ============================================================
if (-not $SkipClient) {
    Write-Status "Step 2/4: Installing Client Dependencies" "Yellow"
    
    Push-Location client
    try {
        Write-Host "Running npm install..." -ForegroundColor Gray
        npm install
        if ($LASTEXITCODE -ne 0) {
            Pop-Location
            Write-Error-Exit "npm install failed"
        }
        Write-Host "✅ Client dependencies installed" -ForegroundColor Green
    } finally {
        Pop-Location
    }
    
    # ============================================================
    # Step 3: Build Client (Production Build)
    # ============================================================
    Write-Status "Step 3/4: Building Client Application" "Yellow"
    
    Push-Location client
    try {
        Write-Host "Running npm run build..." -ForegroundColor Gray
        npm run build
        if ($LASTEXITCODE -ne 0) {
            Pop-Location
            Write-Error-Exit "npm run build failed"
        }
        
        if (-not (Test-Path "dist")) {
            Pop-Location
            Write-Error-Exit "Build succeeded but dist folder not found"
        }
        Write-Host "✅ Client build completed" -ForegroundColor Green
        Write-Host "   Output: dist/" -ForegroundColor Gray
    } finally {
        Pop-Location
    }
} else {
    Write-Host "⏭️  Skipping client build (--SkipClient flag set)" -ForegroundColor Yellow
}

# ============================================================
# Step 4: Build Docker Images
# ============================================================
if (-not $SkipDocker) {
    Write-Status "Step 4/4: Building Docker Images" "Yellow"
    
    $images = @(
        @{ name = "minmsgr-gateway"; dockerfile = "Dockerfile.gateway" },
    )
    
    $dockerfileCount = 0
    foreach ($image in $images) {
        $dockerfilePath = $image.dockerfile
        if (Test-Path $dockerfilePath) {
            Write-Host "Building $($image.name)..." -ForegroundColor Gray
            docker build -f $dockerfilePath -t "minmsgr/$($image.name):latest" .
            if ($LASTEXITCODE -ne 0) {
                Write-Error-Exit "Docker build failed for $($image.name)"
            }
            Write-Host "✅ $($image.name)" -ForegroundColor Green
            $dockerfileCount++
        }
    }
    
    if ($dockerfileCount -eq 0) {
        Write-Host "⚠️  No Dockerfile found" -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "✅ Built $dockerfileCount Docker image(s)" -ForegroundColor Green
    }
} else {
    Write-Host "⏭️  Skipping Docker build (--SkipDocker flag set)" -ForegroundColor Yellow
}

# ============================================================
# Summary
# ============================================================
Write-Status "Build Complete!" "Green"
Write-Host "✅ All build steps completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Start services:"
Write-Host "   - PostgreSQL and Kafka (or use: docker-compose up -d)"
Write-Host "2. Run server:"
Write-Host "   - server\gateway.exe"
Write-Host "3. Start client (dev mode):"
Write-Host "   - cd client && npm run dev"
Write-Host "4. Open browser:"
Write-Host "   - http://localhost:5173"
Write-Host ""
Write-Host "For production Docker deployment:" -ForegroundColor Cyan
Write-Host "  docker-compose build && docker-compose up -d"
Write-Host ""
Write-Host "Build flags:" -ForegroundColor Gray
Write-Host "  -SkipWasm    Skip WASM compilation"
Write-Host "  -SkipClient  Skip npm install/build"
Write-Host "  -SkipDocker  Skip Docker image builds"
Write-Host ""
