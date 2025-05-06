import React, { useState, useEffect } from 'react';

/**
 * VULNERABLE SVG Viewer Component
 * This component intentionally contains unsafe SVG rendering practices
 * for demonstration purposes. DO NOT USE IN PRODUCTION.
 */
const SVGViewer = ({ svgId }) => {
    const [svgContent, setSvgContent] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        // VULNERABLE: Fetching and rendering SVG without sanitization
        const fetchSVG = async () => {
            try {
                const response = await fetch(`/api/svg/${svgId}`);
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error('Failed to load SVG');
                }
                
                // VULNERABLE: Directly setting SVG content without sanitization
                setSvgContent(data.svg_content);
                setLoading(false);
            } catch (err) {
                setError(err.message);
                setLoading(false);
            }
        };

        fetchSVG();
    }, [svgId]);

    // VULNERABLE: Raw SVG string with script and foreignObject
    const rawSvgExample = `
        <svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
            <script>
                console.log("SVG script executed");
                alert("XSS in SVG component");
            </script>
            <rect x="10" y="10" width="80" height="80" fill="green" />
            <foreignObject width="100" height="50" x="10" y="10">
                <body xmlns="http://www.w3.org/1999/xhtml">
                    <div>HTML in SVG</div>
                    <script>alert("XSS via foreignObject")</script>
                </body>
            </foreignObject>
        </svg>
    `;

    if (loading) return <div>Loading SVG...</div>;
    if (error) return <div>Error: {error}</div>;

    return (
        <div className="svg-viewer">
            <h2>SVG Viewer Component</h2>
            
            {/* VULNERABLE: Using dangerouslySetInnerHTML with unsanitized SVG */}
            <div 
                className="svg-container"
                dangerouslySetInnerHTML={{ __html: svgContent }}
            />
            
            <h3>Raw SVG Example:</h3>
            {/* VULNERABLE: Using dangerouslySetInnerHTML with hardcoded SVG that contains script */}
            <div 
                className="example-svg" 
                dangerouslySetInnerHTML={{ __html: rawSvgExample }} 
            />
            
            {/* VULNERABLE: Direct DOM manipulation with SVG */}
            <div className="unsafe-svg" ref={(el) => {
                if (el) {
                    el.innerHTML = svgContent; // VULNERABLE: Direct innerHTML assignment
                }
            }}/>
        </div>
    );
};

// VULNERABLE: Another component showing another pattern
export const InlineSVGRenderer = ({ data }) => {
    // VULNERABLE: Unsafe SVG rendering pattern
    return (
        <div className="inline-svg-container">
            <div dangerouslySetInnerHTML={{ __html: data.svgContent }} />
        </div>
    );
};

export default SVGViewer;