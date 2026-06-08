from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from sangraph_logging import setup_logging
from base_opencode import agent


SANITIZER_CODE = r"""<?php
error_reporting(0);

// 回调函数定义
function xss_entity_decode_callback($matches) {
    return $matches[0];
}

// 模拟获取用户提交的评论内容
$payload = isset($_GET['payload']) ? $_GET['payload'] : '';
$content = $payload;

$out = html_entity_decode(html_entity_decode($content));

$out = strip_tags($out);

$out = preg_replace_callback('/\\([0-9a-f]{4})/i', 'xss_entity_decode_callback', $out);

$out = preg_replace('#/\\\*.*\\\*/#Ums', '', $out);
/**
 * --- 无害化处理结束 ---
 */

?>
<!DOCTYPE html>
<html>
<head><title>健壮性测试页面</title></head>
<body>
    <h3>SVG message preview</h3>
    <svg xmlns="http://www.w3.org/2000/svg" width="320" height="120" viewBox="0 0 320 120">
        <style><?php echo $out; ?></style>
        <rect x="0" y="0" width="320" height="120" fill="#f7f7f7"></rect>
        <text x="16" y="64">Roundcube mail preview</text>
    </svg>
</body>
</html>
"""


async def main() -> None:
    audit_dir = ROOT / "other" / "artifacts" / "audit" / "manual-roundcube-svg"
    result = await agent.run_analysis_with_audit(
        repo_path=None,
        patch_path=None,
        sanitizer_code=SANITIZER_CODE,
        audit_dir=audit_dir,
    )
    print(
        json.dumps(
            {
                "audit_dir": str(audit_dir),
                "input_mode": result.get("input_mode"),
                "input_source": result.get("input_source"),
                "final_verdict_source": result.get("final_verdict_source"),
                "result": result["result"].model_dump(mode="json"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    setup_logging()
    asyncio.run(main())
