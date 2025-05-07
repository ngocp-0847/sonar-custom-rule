<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SVG Upload</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        form {
            border: 1px solid #ddd;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        textarea {
            width: 100%;
            height: 200px;
            font-family: monospace;
        }
        button {
            padding: 10px 15px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #45a049;
        }
        .tab {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            margin-bottom: 20px;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            color: black;
        }
        .tab button:hover {
            background-color: #ddd;
        }
        .tab button.active {
            background-color: #ccc;
        }
        .tabcontent {
            display: none;
            padding: 6px 12px;
            border: 1px solid #ccc;
            border-top: none;
        }
    </style>
</head>
<body>
    <h1>SVG Upload</h1>
    
    <div class="tab">
        <button class="tablinks" onclick="openTab(event, 'FileUpload')" id="defaultOpen">File Upload</button>
        <button class="tablinks" onclick="openTab(event, 'StringUpload')">SVG String</button>
        <button class="tablinks" onclick="openTab(event, 'Examples')">Examples</button>
    </div>
    
    <div id="FileUpload" class="tabcontent">
        <h2>Upload SVG File</h2>
        <!-- VULNERABLE: File upload without proper sanitization -->
        <form action="{{ route('svg.upload') }}" method="POST" enctype="multipart/form-data">
            @csrf
            <div class="form-group">
                <label for="svg_file">Choose an SVG file:</label>
                <input type="file" name="svg_file" id="svg_file" accept="image/svg+xml">
            </div>
            <button type="submit">Upload</button>
        </form>
    </div>
    
    <div id="StringUpload" class="tabcontent">
        <h2>Paste SVG Code</h2>
        <!-- VULNERABLE: SVG string upload without sanitization -->
        <form action="{{ route('svg.upload.string') }}" method="POST">
            @csrf
            <div class="form-group">
                <label for="svg_string">SVG Content:</label>
                <textarea name="svg_string" id="svg_string" placeholder="<svg>...</svg>"></textarea>
            </div>
            <button type="submit">Upload</button>
        </form>
    </div>
    
    <div id="Examples" class="tabcontent">
        <h2>Example SVG Code</h2>
        <p>Here are some example SVG codes you can use:</p>
        
        <h3>Basic Circle</h3>
        <pre>&lt;svg width="100" height="100"&gt;
  &lt;circle cx="50" cy="50" r="40" stroke="black" stroke-width="2" fill="red" /&gt;
&lt;/svg&gt;</pre>
        
        <h3>Basic Shape with Script (Potentially Dangerous)</h3>
        <pre>&lt;svg width="100" height="100"&gt;
  &lt;rect x="10" y="10" width="80" height="80" fill="blue" /&gt;
  &lt;script&gt;alert('XSS in SVG');&lt;/script&gt;
&lt;/svg&gt;</pre>

        <h3>SVG with foreignObject (Potentially Dangerous)</h3>
        <pre>&lt;svg width="200" height="200"&gt;
  &lt;foreignObject width="100%" height="100%"&gt;
    &lt;body xmlns="http://www.w3.org/1999/xhtml"&gt;
      &lt;div&gt;HTML content inside SVG&lt;/div&gt;
      &lt;script&gt;alert('XSS via foreignObject');&lt;/script&gt;
    &lt;/body&gt;
  &lt;/foreignObject&gt;
&lt;/svg&gt;</pre>
    </div>
    
    <script>
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    
    // Open the default tab on page load
    document.getElementById("defaultOpen").click();
    </script>
</body>
</html>