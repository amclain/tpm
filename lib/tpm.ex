defmodule TPM do
  @moduledoc """
  Use a Trusted Platform Module (TPM) with Elixir and Nerves.
  """

  def clear do
    case cmd("tpm2_clear", []) do
      {:ok, _} -> :ok
      error    -> error
    end
  end

  def generate_private_key(output_path) do
    case cmd("tpm2tss-genkey", ["-a", "ecdsa", output_path]) do
      {:ok, _} -> :ok
      error    -> error
    end
  end

  def nvdefine(opts \\ []) do
    args =
      Enum.reduce(opts, [], fn
        {:size, size}, acc ->
          acc ++ ["-s", to_string(size)]

        {_, _}, acc ->
          acc
      end)

    case cmd("tpm2_nvdefine", args) do
      {:ok, stdout} ->
        # stdout format:
        # nv-index: 0x1000001
        address =
          stdout
          |> String.split
          |> List.last

        {:ok, address}

      error ->
        error
    end
  end

  def nvread(address, opts \\ []) do
    args =
      Enum.reduce(opts, [], fn
        {:output, path}, acc ->
          acc ++ ["-o", path]

        {_, _}, acc ->
          acc
      end)

    cmd("tpm2_nvread", args ++ [address])
  end

  def nvwrite(address, path) do
    case cmd("tpm2_nvwrite", ["-i", path, address]) do
      {:ok, _} -> :ok
      error    -> error
    end
  end

  defp cmd(command, args, opts \\ []) do
    opts = opts ++ [stderr_to_stdout: true]

    case MuonTrap.cmd(command, args, opts) do
      {stdout, 0}     -> {:ok, stdout}
      {message, code} -> {:error, code, message}
    end
  end
end
