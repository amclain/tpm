# TPM

Use a Trusted Platform Module (TPM) with Elixir and [Nerves](https://nerves-project.org/).

A TPM can be used to secure the cryptographic keys used for things like SSL/TLS
connections and disk encryption.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `tpm` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tpm, "~> 0.0.1"}
  ]
end
```
