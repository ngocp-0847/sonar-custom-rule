<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dangerous SVG Example</title>
    <style>
        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .svg-container {
            width: 200px;
            height: 200px;
            border: 2px solid red;
            padding: 10px;
            margin: 20px auto;
        }
    </style>
</head>
<body>
    <h1>Dangerous SVG Example</h1>
    
    <div class="warning">
        <strong>Warning:</strong> This page intentionally demonstrates SVG vulnerabilities by rendering SVG content 
        that contains script and foreignObject elements. In a real application, this would allow for XSS attacks.
    </div>
    
    <h2>Vulnerable SVG with script and foreignObject:</h2>
    
    <div class="svg-container">
        <!-- VULNERABLE: Directly rendering SVG with script and foreignObject -->
        {!! $svg !!}
    </div>
    
    <h2>Code Analysis:</h2>
    <div>
        <p>The above SVG contains:</p>
        <ul>
            <li>A &lt;script&gt; tag that could execute arbitrary JavaScript</li>
            <li>A &lt;foreignObject&gt; element that allows embedding HTML inside SVG</li>
            <li>Event handlers that could execute when the SVG is interacted with</li>
        </ul>
        <p>All of these are entry points for Cross-Site Scripting (XSS) attacks.</p>
    </div>
    
    <h2>Another Example with inline handler:</h2>
    <div class="svg-container">
        <!-- VULNERABLE: SVG with event handlers -->
        <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="40" stroke="black" fill="red"
                onmouseover="alert('XSS via event handler');" />
            <use href="data:image/svg+xml,&lt;svg id='x' xmlns='http://www.w3.org/2000/svg'&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/svg&gt;#x" />
        </svg>
    </div>
    
    <script>
        // VULNERABLE: Dynamically creating and injecting SVG
        const svgWithXSS = '<svg width="50" height="50">' + 
                           '<script>console.log("Injected via JS");</script>' +
                           '<circle cx="25" cy="25" r="20" fill="blue" />' +
                           '</svg>';
        document.getElementById('js-injected').innerHTML = svgWithXSS;
    </script>
    
    <div id="js-injected"></div>
</body>
</html>