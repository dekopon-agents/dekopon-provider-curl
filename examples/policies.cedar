// Example only: replace both identifiers. Cedar decides who may invoke curl.get; the constraint
// set independently binds method, exact authority, request count, bytes, and timeout.
permit(
    principal == Dekopon::Principal::"example-caller",
    action == Dekopon::Action::"curl.get",
    resource == Dekopon::Provider::"curl"
) when {
    context has agent && context.agent == "example-agent"
} unless {
    context has via
};
