defmodule DemoElixirAudit.MixProject do
  use Mix.Project

  def project do
    [app: :demo_elixir_audit, version: "0.1.0"]
  end

  defp deps do
    [
      {:plug, "1.11.0"},
      {:jason, "1.4.1"}
    ]
  end
end
