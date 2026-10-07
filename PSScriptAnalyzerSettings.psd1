@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # These are interactive console scripts: colored progress output for a
        # person watching the deployment is the intended behavior.
        'PSAvoidUsingWriteHost'
    )
}
