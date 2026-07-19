# WhereIAmService

Azure function which support WhereIAm iOS/iPadOS app.  Takes a simple GET,
and returns a JSON bundle describing the external IP of the request, and the
location info for that address.



Status end-point:  https://wiafunc-ezdphsfxarecfhhk.northeurope-01.azurewebsites.net/admin/host/status

Lookup:         https://wiafunc-ezdphsfxarecfhhk.northeurope-01.azurewebsites.net/api/geolookup

App key required, from Azure Portal Function, under default.
