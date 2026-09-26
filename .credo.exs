%{
  configs: [
    %{
      name: "default",
      checks: %{
        enabled: [{Credo.Check.Readability.MaxLineLength, max_length: 200}]
      }
    }
  ]
}
