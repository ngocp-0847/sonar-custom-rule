<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SVG Gallery</title>
    <style>
        .gallery {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            padding: 20px;
        }
        .svg-item {
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
        }
        .svg-container {
            width: 150px;
            height: 150px;
            margin: 0 auto;
        }
    </style>
</head>
<body>
    <h1>SVG Gallery</h1>
    
    <div class="gallery">
        @foreach($svgs as $item)
            <div class="svg-item">
                <h3>{{ $item->filename }}</h3>
                
                <div class="svg-container">
                    <!-- VULNERABLE: Direct unescaped output of SVG content -->
                    {!! $item->svg_content !!}
                </div>
                
                <div>
                    <a href="{{ route('svg.display', $item->id) }}">View</a>
                    <a href="{{ route('svg.raw', $item->id) }}">Download</a>
                </div>
            </div>
        @endforeach
    </div>
    
    <div class="svg-preview" id="dynamicPreview"></div>
    
    <script>
        // VULNERABLE: Loading SVGs dynamically with no sanitization
        async function loadSvg(id) {
            const response = await fetch(`/api/svg/${id}`);
            const data = await response.json();
            
            // VULNERABLE: Using innerHTML with unsanitized SVG content
            document.getElementById('dynamicPreview').innerHTML = data.svg_content;
        }
        
        // VULNERABLE: Directly assigning SVG content to DOM
        @foreach($svgs as $item)
            document.querySelector('.svg-item-{{ $item->id }}').innerHTML = `{!! addslashes($item->svg_content) !!}`;
        @endforeach
    </script>
</body>
</html>