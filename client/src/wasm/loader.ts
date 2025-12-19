// WASM loader for Go-compiled wasm modules
// Dynamically loads wasm_exec.js to set up Go runtime

async function loadGoRuntime(): Promise<boolean> {
  return new Promise((resolve) => {
    // Check if already loaded
    if (typeof (window as any).Go !== 'undefined') {
      console.log('[Loader] ✅ Go runtime already loaded');
      resolve(true);
      return;
    }

    console.log('[Loader] 📥 Loading wasm_exec.js...');
    const script = document.createElement('script');
    script.src = '/wasm_exec.js';
    script.type = 'text/javascript';
    
    script.onload = () => {
      console.log('[Loader] ✅ wasm_exec.js loaded');
      // Wait a bit for wasm_exec to fully initialize
      setTimeout(() => {
        if (typeof (window as any).Go !== 'undefined') {
          console.log('[Loader] ✅ Go runtime available');
          resolve(true);
        } else {
          console.error('[Loader] ❌ wasm_exec.js loaded but Go not available');
          resolve(false);
        }
      }, 100);
    };
    
    script.onerror = (err) => {
      console.error('[Loader] ❌ Failed to load wasm_exec.js:', err);
      resolve(false);
    };
    
    document.head.appendChild(script);
  });
}

export async function initGoWasm(wasmPath: string): Promise<boolean> {
  console.log('[Loader] Starting Go WASM initialization...');
  
  // First ensure Go runtime is loaded
  const goLoaded = await loadGoRuntime();
  if (!goLoaded) {
    console.error('[Loader] ❌ Go runtime not available');
    return false;
  }

  try {
    console.log('[Loader] 🚀 Creating Go instance...');
    const go = new (window as any).Go();
    console.log('[Loader] ✅ Go instance created');
    console.log('[Loader] Go instance properties:', {
      hasImportObject: 'importObject' in go,
      importObjectType: typeof (go as any).importObject,
      isGetter: Object.getOwnPropertyDescriptor(Object.getPrototypeOf(go), 'importObject')?.get ? 'yes' : 'no',
    });
    
    // Handle both old and new wasm_exec.js versions
    // Old version (< 1.21): importObject is a method
    // New version (>= 1.21): importObject is a property
    let importObject: any;
    if (typeof go.importObject === 'function') {
      // Old wasm_exec.js style - call it as a function
      importObject = go.importObject();
      console.log('[Loader] ℹ️ Using importObject() function (old wasm_exec.js)');
    } else if (go.importObject && typeof go.importObject === 'object') {
      // New wasm_exec.js style - use as property
      importObject = go.importObject;
      console.log('[Loader] ℹ️ Using importObject property (new wasm_exec.js)');
    } else {
      console.warn('[Loader] ⚠️ go.importObject not properly initialized, using empty fallback');
      // Create fallback
      importObject = { go: {}, env: {} };
    }
    

    console.log(`[Loader] 📦 Fetching WASM from: ${wasmPath}`);
    
    // Fetch the WASM file
    const resp = await fetch(wasmPath);
    if (!resp.ok) throw new Error(`Failed to fetch ${wasmPath} - status ${resp.status}`);
    
    const contentLength = resp.headers.get('content-length');
    console.log(`[Loader] ✅ Fetched WASM, size: ${contentLength} bytes`);
    
    const bytes = await resp.arrayBuffer();
    console.log(`[Loader] 📥 Loaded ${bytes.byteLength} bytes`);
    
    // Verify the magic number
    const view = new Uint8Array(bytes);
    if (view[0] !== 0 || view[1] !== 0x61 || view[2] !== 0x73 || view[3] !== 0x6d) {
      throw new Error(`Invalid WebAssembly magic number. Expected 00 61 73 6d, got ${view[0].toString(16)} ${view[1].toString(16)} ${view[2].toString(16)} ${view[3].toString(16)}`);
    }
    
    console.log('[Loader] 🔧 Instantiating WebAssembly...');
    try {
      const result = await WebAssembly.instantiate(bytes, importObject);
      console.log('[Loader] ✅ WebAssembly instantiated successfully');
      
      console.log('[Loader] ▶️ Running WASM module...');
      // Run the Go program - this will block and the program will stay running
      // We use a non-awaited call so it can run in the background
      Promise.resolve().then(() => {
        go.run(result.instance);
      }).catch(err => {
        console.error('[Loader] ❌ Go program execution error:', err);
      });
      
      // Give the program a moment to initialize
      await new Promise(resolve => setTimeout(resolve, 500));
      
      console.log('[Loader] ✅ WASM module running!');
      return true;
    } catch (err) {
      console.error('[Loader] ❌ WASM instantiation failed:', err);
      if (err instanceof Error) {
        console.error('[Loader] Error details:', {
          message: err.message,
          name: err.name,
        });
        // Try to extract import info from error
        if (err.message.includes('Import')) {
          console.error('[Loader] This looks like an import mismatch error');
          console.error('[Loader] WASM expects different imports than what we provided');
        }
      }
      throw err;
    }
  } catch (err) {
    console.error('[Loader] ❌ WASM init failed:', err);
    if (err instanceof Error) {
      console.error('[Loader] Error message:', err.message);
      console.error('[Loader] Error stack:', err.stack);
    }
    console.error('[Loader] Debug info - go.importObject:', (window as any).Go ? 'Go exists' : 'Go missing');
    return false;
  }
}
