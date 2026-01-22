#!/usr/bin/env python3
"""
Optimized Large Log File Analyzer
Fast processing with priority sorting (errors/warnings first)
"""

import re
import sys
from collections import defaultdict
from datetime import datetime
import hashlib

def normalize_log_line(line):
    """Normalize log line for duplicate detection"""
    normalized = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', line)
    normalized = re.sub(r'\d{2}:\d{2}:\d{2}', 'TIME', normalized)
    normalized = re.sub(r'\b\d+\b', 'NUM', normalized)
    return normalized

def detect_log_level(line):
    """Detect the severity level of the log line"""
    line_lower = line.lower()
    if any(keyword in line_lower for keyword in ['error', 'exception', 'fail', 'fatal', 'critical']):
        return 'error'
    elif any(keyword in line_lower for keyword in ['warn', 'warning']):
        return 'warning'
    else:
        return 'info'

def analyze_log_file(file_path, max_lines=None):
    """Analyze log file and return structured data with priority sorting"""
    print(f"Analyzing {file_path}...")
    
    # Separate lists for different log levels (for faster sorting)
    errors = []
    warnings = []
    info_logs = []
    
    duplicate_map = defaultdict(lambda: {'count': 0, 'lines': [], 'first_occurrence': None})
    
    line_count = 0
    errors_count = 0
    warnings_count = 0
    duplicates_count = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if max_lines and line_num > max_lines:
                    print(f"Stopped at {max_lines} lines (limit reached)")
                    break
                
                line = line.rstrip('\n\r')
                if not line.strip():
                    continue
                
                line_count += 1
                
                # Detect level
                level = detect_log_level(line)
                
                # Track errors and warnings for duplicate detection
                is_duplicate = False
                dup_count = 0
                
                if level in ['error', 'warning']:
                    normalized = normalize_log_line(line)
                    hash_key = hashlib.md5(normalized.encode()).hexdigest()
                    
                    duplicate_map[hash_key]['count'] += 1
                    duplicate_map[hash_key]['lines'].append(line_num)
                    
                    if duplicate_map[hash_key]['first_occurrence'] is None:
                        duplicate_map[hash_key]['first_occurrence'] = line_num
                    
                    if duplicate_map[hash_key]['count'] > 1:
                        is_duplicate = True
                        dup_count = duplicate_map[hash_key]['count']
                        duplicates_count += 1
                    
                    if level == 'error' and not is_duplicate:
                        errors_count += 1
                    elif level == 'warning' and not is_duplicate:
                        warnings_count += 1
                
                log_entry = {
                    'line_num': line_num,
                    'content': line,
                    'level': level,
                    'is_duplicate': is_duplicate,
                    'dup_count': dup_count
                }
                
                # Add to appropriate list for pre-sorting
                if level == 'error':
                    errors.append(log_entry)
                elif level == 'warning':
                    warnings.append(log_entry)
                else:
                    info_logs.append(log_entry)
                
                # Progress indicator
                if line_count % 10000 == 0:
                    print(f"Processed {line_count:,} lines...")
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    print(f"Analysis complete: {line_count:,} lines processed")
    print(f"Sorting logs (errors first)...")
    
    # Combine in priority order: errors -> warnings -> info
    # Within each category, non-duplicates first
    sorted_logs = (
        sorted(errors, key=lambda x: (x['is_duplicate'], x['line_num'])) +
        sorted(warnings, key=lambda x: (x['is_duplicate'], x['line_num'])) +
        info_logs[:5000]  # Limit info logs to keep report manageable
    )
    
    stats = {
        'total': line_count,
        'errors': errors_count,
        'warnings': warnings_count,
        'duplicates': duplicates_count
    }
    
    return sorted_logs, stats

def generate_html_report(logs, stats, output_file='log_report.html'):
    """Generate an interactive HTML report"""
    print(f"Generating HTML report: {output_file}")
    
    # Limit display for performance
    display_limit = min(len(logs), 20000)
    
    log_entries_html = []
    
    for i, log in enumerate(logs[:display_limit]):
        css_class = log['level']
        if log['is_duplicate']:
            css_class = 'duplicate'
        
        dup_badge = f'<span class="dup-badge">Duplicate #{log["dup_count"]}</span>' if log['is_duplicate'] else ''
        
        entry_html = f"""        <div class="log-entry {css_class}" data-level="{log['level']}" data-dup="{str(log['is_duplicate']).lower()}">
            <div class="log-meta">
                <span class="line-num">Line {log['line_num']}</span>
                {dup_badge}
                <button class="copy-btn" onclick="copyLog(this, {log['line_num']})" title="Copy to clipboard">
                    <span class="copy-icon">📋</span>
                    <span class="copied-icon" style="display:none;">✓</span>
                </button>
            </div>
            <div class="log-content" data-original="{html_escape(log['content'])}">{html_escape(log['content'][:500])}</div>
        </div>"""
        log_entries_html.append(entry_html)
    
    if len(logs) > display_limit:
        log_entries_html.append(f"""
        <div style="padding: 20px; text-align: center; background: #fef3c7; border-radius: 6px; margin-top: 20px;">
            <strong>Note:</strong> Showing top {display_limit:,} priority entries (errors & warnings first) of {stats['total']:,} total lines.
        </div>""")
    
    logs_html = '\n'.join(log_entries_html)
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; margin-bottom: 10px; }}
        .subtitle {{ color: #666; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-label {{ color: #666; font-size: 14px; margin-bottom: 5px; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .stat-card.total .stat-value {{ color: #333; }}
        .stat-card.errors .stat-value {{ color: #dc2626; }}
        .stat-card.warnings .stat-value {{ color: #ca8a04; }}
        .stat-card.duplicates .stat-value {{ color: #6b7280; }}
        .filters {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }}
        .filter-btn {{ padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }}
        .filter-btn:hover {{ transform: translateY(-1px); }}
        .filter-btn.active {{ box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .filter-btn.all {{ background: #3b82f6; color: white; }}
        .filter-btn.errors {{ background: #dc2626; color: white; }}
        .filter-btn.warnings {{ background: #ca8a04; color: white; }}
        .filter-btn.duplicates {{ background: #6b7280; color: white; }}
        .filter-btn.info {{ background: #0891b2; color: white; }}
        .logs-container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-height: 800px; overflow-y: auto; }}
        .log-entry {{ padding: 12px; margin-bottom: 8px; border-radius: 6px; border-left: 4px solid; font-family: 'Courier New', monospace; font-size: 13px; }}
        .log-entry.error {{ background: #fef2f2; border-color: #dc2626; color: #991b1b; }}
        .log-entry.warning {{ background: #fefce8; border-color: #ca8a04; color: #854d0e; }}
        .log-entry.info {{ background: #f0f9ff; border-color: #0891b2; color: #155e75; }}
        .log-entry.duplicate {{ background: #f3f4f6; border-color: #6b7280; color: #374151; opacity: 0.8; }}
        .log-meta {{ display: flex; gap: 10px; align-items: center; margin-bottom: 5px; font-size: 11px; }}
        .line-num {{ background: rgba(0,0,0,0.1); padding: 2px 6px; border-radius: 3px; }}
        .dup-badge {{ background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 3px; }}
        .copy-btn {{ background: rgba(0,0,0,0.05); border: none; padding: 4px 8px; border-radius: 3px; cursor: pointer; font-size: 14px; transition: all 0.2s; margin-left: auto; }}
        .copy-btn:hover {{ background: rgba(0,0,0,0.1); transform: scale(1.1); }}
        .copy-btn:active {{ transform: scale(0.95); }}
        .log-content {{ white-space: pre-wrap; word-break: break-word; }}
        .hidden {{ display: none !important; }}
        .search-box {{ width: 100%; padding: 10px; border: 2px solid #e5e7eb; border-radius: 6px; font-size: 14px; margin-bottom: 15px; }}
        .search-box:focus {{ outline: none; border-color: #3b82f6; }}
        .info-banner {{ background: #dbeafe; border-left: 4px solid #3b82f6; padding: 15px; border-radius: 6px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Log Analysis Report</h1>
        <p class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="info-banner">
            <strong>📊 Logs sorted by priority:</strong> Errors first, then warnings, then info logs. 
            Non-duplicates shown before duplicates within each category.
        </div>
        
        <div class="stats">
            <div class="stat-card total">
                <div class="stat-label">Total Lines</div>
                <div class="stat-value">{stats['total']:,}</div>
            </div>
            <div class="stat-card errors">
                <div class="stat-label">Errors</div>
                <div class="stat-value">{stats['errors']:,}</div>
            </div>
            <div class="stat-card warnings">
                <div class="stat-label">Warnings</div>
                <div class="stat-value">{stats['warnings']:,}</div>
            </div>
            <div class="stat-card duplicates">
                <div class="stat-label">Duplicates</div>
                <div class="stat-value">{stats['duplicates']:,}</div>
            </div>
        </div>
        
        <div class="filters">
            <button class="filter-btn all active" onclick="filterLogs('all')">All</button>
            <button class="filter-btn errors" onclick="filterLogs('error')">Errors Only ({stats['errors']:,})</button>
            <button class="filter-btn warnings" onclick="filterLogs('warning')">Warnings Only ({stats['warnings']:,})</button>
            <button class="filter-btn duplicates" onclick="filterLogs('duplicate')">Duplicates Only ({stats['duplicates']:,})</button>
            <button class="filter-btn info" onclick="filterLogs('info')">Info Only</button>
        </div>
        
        <div class="logs-container" id="logsContainer">
            <input type="text" class="search-box" id="searchBox" placeholder="Search logs (press Enter)..." onkeyup="if(event.key==='Enter') searchLogs()">
            <div id="logsContent">
{logs_html}
            </div>
        </div>
    </div>
    
    <script>
        let currentFilter = 'all';
        const entries = document.querySelectorAll('.log-entry');
        
        function copyLog(button, lineNum) {{
            const logEntry = button.closest('.log-entry');
            const content = logEntry.querySelector('.log-content').getAttribute('data-original');
            const textToCopy = `Line ${{lineNum}}: ${{content}}`;
            
            navigator.clipboard.writeText(textToCopy).then(() => {{
                // Show checkmark
                button.querySelector('.copy-icon').style.display = 'none';
                button.querySelector('.copied-icon').style.display = 'inline';
                
                // Reset after 2 seconds
                setTimeout(() => {{
                    button.querySelector('.copy-icon').style.display = 'inline';
                    button.querySelector('.copied-icon').style.display = 'none';
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy:', err);
                alert('Failed to copy to clipboard');
            }});
        }}
        
        function filterLogs(filter) {{
            currentFilter = filter;
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            document.querySelector('.filter-btn.' + filter).classList.add('active');
            
            entries.forEach(entry => {{
                const level = entry.getAttribute('data-level');
                const isDup = entry.getAttribute('data-dup') === 'true';
                
                if (filter === 'all') {{
                    entry.classList.remove('hidden');
                }} else if (filter === 'duplicate') {{
                    entry.classList.toggle('hidden', !isDup);
                }} else {{
                    entry.classList.toggle('hidden', level !== filter);
                }}
            }});
            
            document.getElementById('searchBox').value = '';
        }}
        
        function searchLogs() {{
            const searchText = document.getElementById('searchBox').value.toLowerCase();
            
            if (!searchText) {{
                filterLogs(currentFilter);
                return;
            }}
            
            entries.forEach(entry => {{
                const content = entry.textContent.toLowerCase();
                const matchesSearch = content.includes(searchText);
                entry.classList.toggle('hidden', !matchesSearch);
            }});
        }}
    </script>
</body>
</html>"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"Report generated successfully: {output_file}")
    return output_file

def html_escape(text):
    """Escape HTML special characters"""
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))

def main():
    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py <log_file_path> [max_lines]")
        print("\nExample:")
        print("  python log_analyzer.py app.log")
        print("  python log_analyzer.py app.log 100000")
        sys.exit(1)
    
    log_file = sys.argv[1]
    max_lines = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    print("=" * 60)
    print("LOG FILE ANALYZER - OPTIMIZED VERSION")
    print("=" * 60)
    
    # Analyze the log file
    logs, stats = analyze_log_file(log_file, max_lines)
    
    # Generate HTML report
    output_file = generate_html_report(logs, stats)
    
    print("\n" + "=" * 60)
    print(f"✓ Analysis complete!")
    print(f"✓ Errors and warnings prioritized at top")
    print(f"✓ Open {output_file} in your browser to view the report")
    print("=" * 60)

if __name__ == '__main__':
    main()
