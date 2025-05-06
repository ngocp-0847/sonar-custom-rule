<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SVG Display</title>
    <style>
        .svg-container {
            width: 400px;
            height: 400px;
            border: 1px solid #ccc;
            margin: 20px auto;
        }
    </style>
</head>
<body>
    <h1>SVG Display</h1>
    
    <div class="svg-container">
        <!-- VULNERABLE: Unsafe rendering of SVG content with {!! !!} -->
        <!-- This will execute any script or foreignObject elements in the SVG -->
        {!! $svg !!}
    </div>
    
    <div>
        <h3>Raw SVG Code:</h3>
        <pre>{{ $svg }}</pre>
    </div>
    
    <script>
        // VULNERABLE: Directly embedding SVG in JavaScript
        const svgContent = '{!! addslashes($svg) !!}';
        
        // VULNERABLE: Using innerHTML with SVG content
        document.querySelector('.svg-duplicate').innerHTML = svgContent;
    </script>
</body>
</html>