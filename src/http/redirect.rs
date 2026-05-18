pub fn extract_redirect_url(response: &crate::http::response::HttpResponse) -> Option<String> {
    response
        .headers
        .get("location")
        .or_else(|| response.headers.get("Location"))
        .cloned()
}
