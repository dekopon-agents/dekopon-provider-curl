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

// Naming a DRN on argv authorizes nothing by itself. Each secret this caller may have rendered into
// an Authorization header needs its own statement, for that exact DRN, capability, provider, and
// sink, and an owner-authored binding in the secret map besides.
@id("example-caller-may-use-the-api-token")
permit(
    principal == Dekopon::Principal::"example-caller",
    action == Dekopon::Action::"secret.use",
    resource == Dekopon::Secret::"drn:com.xrl:secret:prod:api/token"
) when {
    context.capability == "curl.get"
    && context.provider == "curl"
    && context.sink == "httpBearer"
};
