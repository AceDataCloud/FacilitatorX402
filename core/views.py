from django.http import HttpResponse, JsonResponse

HOME_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Ace Data Cloud · Facilitator X402</title>
<style>
    :root {
        font-family: "Space Grotesk", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        color: #0f172a;
        background: radial-gradient(circle at top, #eff6ff, #ffffff 45%);
    }
    body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .hero {
        width: min(960px, 92vw);
        padding: 3rem 3.5rem;
        border-radius: 32px;
        background: rgba(255, 255, 255, 0.9);
        box-shadow: 0 20px 45px rgba(15, 23, 42, 0.08);
        border: 1px solid rgba(59, 130, 246, 0.15);
    }
    .eyebrow {
        text-transform: uppercase;
        font-size: 0.85rem;
        letter-spacing: 0.2em;
        color: #2563eb;
        font-weight: 600;
    }
    h1 {
        font-size: clamp(2.5rem, 4vw, 3.75rem);
        margin: 0.25rem 0 1rem;
    }
    p.lead {
        font-size: 1.15rem;
        line-height: 1.6;
        max-width: 58ch;
    }
    .cta-row {
        margin-top: 2rem;
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
    }
    .cta {
        flex: 1 1 240px;
        padding: 1.25rem;
        border-radius: 18px;
        border: 1px solid rgba(15, 23, 42, 0.08);
        background: #f8fafc;
    }
    .cta h2 {
        margin: 0 0 0.35rem;
        font-size: 1rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #475569;
    }
    code {
        font-size: 0.95rem;
        background: rgba(59, 130, 246, 0.1);
        padding: 0.4rem 0.6rem;
        border-radius: 8px;
        display: inline-block;
    }
    @media (max-width: 640px) {
        .hero {
            padding: 2.5rem 1.75rem;
        }
    }
</style>
</head>
<body>
    <main class="hero">
        <div class="eyebrow">Ace Data Cloud</div>
        <h1>Facilitator X402</h1>
        <p class="lead">
            Production-grade settlement for x402 micropayments. Verify signed authorizations,
            settle stablecoin transfers on-chain, and unlock pay-per-request APIs with a single call.
        </p>
        <div class="cta-row">
            <div class="cta">
                <h2>Verify</h2>
                <p>Validate payload integrity, enforce quotas, and stage the nonce.</p>
                <code>POST /verify</code>
            </div>
            <div class="cta">
                <h2>Settle</h2>
                <p>Submit the stored authorization to the chain and receive the receipt.</p>
                <code>POST /settle</code>
            </div>
        </div>
    </main>
</body>
</html>"""


def home(request):
    return HttpResponse(HOME_PAGE_HTML, content_type="text/html; charset=utf-8")


def health(request):
    return JsonResponse({"status": "ok"})
