
import azure.functions as func
import logging
import json
import urllib.request
import urllib.error

import os

secret_value = os.environ.get("APITOKEN")

if secret_value:
    masked_preview = secret_value[:3] 
    logging.info(f"Secret fetched successfully! Preview: {masked_preview}...")

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


@app.route(route="geolookup", auth_level=func.AuthLevel.FUNCTION)
def geolookup(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing IP geolocation request')

    xff = req.headers.get('X-Forwarded-For')
    if xff:
        client_ip = xff.split(',')[0].strip()
        if client_ip.startswith('['):
            # IPv6 in bracket notation, with or without a port:
            # "[addr]" or "[addr]:port" - strip to just the address.
            client_ip = client_ip[1:client_ip.index(']')]
        elif client_ip.count(':') == 1:
            # IPv4 with a port: "1.2.3.4:12345"
            client_ip = client_ip.split(':')[0]
        # else: bare IPv6 address with no brackets/port - use as-is
    else:
        client_ip = req.headers.get('X-Client-IP') or 'unknown'

    if client_ip == 'unknown':
        return func.HttpResponse("Could not determine client IP", status_code=400)

    geo_data, error_detail = lookup_ip(client_ip)

    if geo_data is None:
        # error_detail carries pro.ip-api.com's own message (or the request
        # exception) so failures are diagnosable from the client without
        # having to go dig through Azure's function logs.
        return func.HttpResponse(
            json.dumps({"error": "Geolocation lookup failed", "ip": client_ip, "detail": error_detail}),
            status_code=502,
            mimetype="application/json"
        )

    return func.HttpResponse(
        json.dumps(geo_data),
        status_code=200,
        mimetype="application/json"
    )


def lookup_ip(ip: str) -> tuple[dict | None, str | None]:
    """Query pro.ip-api.com for lat/long, city, region, country.

    Returns (data, error_detail): on success, (dict, None); on failure,
    (None, <reason string>) so callers can report why without re-deriving it.
    """
    # 'fields' param limits the response to just what we want (also slightly faster)
    fields = "status,message,country,regionName,city,lat,lon,query"
    url = f"https://pro.ip-api.com/json/{ip}?fields={fields}&key={secret_value}"


    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
    except (urllib.error.URLError, TimeoutError) as e:
        logging.error(f"pro.ip-api.com request failed: {e} url={url}")
        return None, f"request failed: {e}"

    if data.get("status") != "success":
        message = data.get("message")
        logging.warning(f"ip-api.com lookup failed: {url} {message}")
        return None, message or "ip-api.com returned a non-success status with no message"

    return {
        "ip": data.get("query"),
        "city": data.get("city"),
        "state": data.get("regionName"),
        "country": data.get("country"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }, None
