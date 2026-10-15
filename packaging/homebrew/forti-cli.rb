# frozen_string_literal: true

# Formula template. `vlr homebrew formula` renders the release url/sha256 into
# release/homebrew/forti-cli.rb, which `vlr homebrew publish` commits to valkyrianlabs/homebrew-tap.
class FortiCli < Formula
  desc "FortiOS command-line interface: discover, read, plan and apply FortiGate config"
  homepage "https://github.com/valkyrianlabs/forti-cli"
  url "https://github.com/valkyrianlabs/forti-cli/releases/download/v0.1.0/forti-cli-0.1.0.tar.gz"
  sha256 "TODO_REPLACE_WITH_RELEASE_ARCHIVE_SHA256"
  license "MIT"
  head "https://github.com/valkyrianlabs/forti-cli.git", branch: "main"

  # Header-only SDK: needed to compile, not at run time.
  depends_on "forti-api" => :build
  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build

  uses_from_macos "curl"

  def install
    # std_meson_args sets --buildtype=release and --wrap-mode=nofallback (stricter than nodownload):
    # forti-api always comes from the forti-api formula, never from subprojects/forti-api.wrap.
    # optimization=3 is meson.build's release profile, repeated so it holds whatever the build type;
    # strip=true installs the binary without its symbol table (24 MB -> 12 MB).
    # The tests need GoogleTest and run in CI; the `test do` block exercises the installed binary.
    system "meson", "setup", "build", "-Dtests=disabled", "-Doptimization=3", "-Dstrip=true", *std_meson_args
    # Each engine shard translation unit needs about 2 GB of RAM: cap the jobs so an 8 GB Mac
    # does not swap.
    system "meson", "compile", "-C", "build", "--jobs", [ENV.make_jobs, 4].min.to_s
    system "meson", "install", "-C", "build"
  end

  test do
    assert_match "forti #{version}", shell_output("#{bin}/forti --version")

    # Offline: the resource catalog is compiled in, so no profile or device is needed.
    ENV["FORTI_HOME"] = (testpath/"forti").to_s
    output = JSON.parse(shell_output("#{bin}/forti --json discover firewall/address"))
    assert output["ok"]
    assert_includes output["data"]["fields"].map { |field| field["name"] }, "subnet"
  end
end
