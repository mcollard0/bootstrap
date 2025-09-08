#!/usr/bin/env python3
"""
Simple HTTP server to serve bootstrap files to VM for testing.
This allows file transfer when guest additions fail.
"""

import http.server;
import socketserver;
import os;
from pathlib import Path;

def main():
    # Set up server in the bootstrap directory
    bootstrap_dir = Path( __file__ ).parent.parent;
    os.chdir( bootstrap_dir );
    
    PORT = 8080;
    
    class BootstrapHTTPRequestHandler( http.server.SimpleHTTPRequestHandler ):
        def end_headers( self ):
            # Add CORS headers for cross-origin requests
            self.send_header( 'Access-Control-Allow-Origin', '*' );
            self.send_header( 'Access-Control-Allow-Methods', 'GET, POST, OPTIONS' );
            self.send_header( 'Access-Control-Allow-Headers', 'Content-Type' );
            super().end_headers();
    
    print( f"🌐 Starting HTTP server on port {PORT}" );
    print( f"📁 Serving files from: {bootstrap_dir}" );
    print( f"🔗 VM can access files at: http://HOST_IP:{PORT}/" );
    print( f"📜 Bootstrap script URL: http://HOST_IP:{PORT}/scripts/bootstrap.sh" );
    print( f"📊 Inventory URL: http://HOST_IP:{PORT}/data/inventory.json" );
    print( f"🔐 Encrypted secrets URL: http://HOST_IP:{PORT}/data/encrypted_secrets.json" );
    print();
    print( "📋 In VM, run:" );
    print( f"   curl -O http://HOST_IP:{PORT}/scripts/bootstrap.sh" );
    print( f"   chmod +x bootstrap.sh" );
    print( f"   sudo ./bootstrap.sh" );
    print();
    print( "Press Ctrl+C to stop server" );
    
    with socketserver.TCPServer( ("", PORT), BootstrapHTTPRequestHandler ) as httpd:
        try:
            httpd.serve_forever();
        except KeyboardInterrupt:
            print( "\n🛑 Server stopped" );

if __name__ == '__main__':
    main();
