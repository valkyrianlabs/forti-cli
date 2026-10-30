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

  # Only homebrew/core dependencies: Homebrew trusts the formulae named on the command line
  # (brew install valkyrianlabs/tap/forti-cli) and refuses to load any other formula from an untrusted
  # third-party tap, build dependencies included, even when it pours a bottle. So forti-api is a
  # resource below, and forti-mcp is named as well when wanted:
  #   brew install valkyrianlabs/tap/forti-cli valkyrianlabs/tap/forti-mcp
  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build

  uses_from_macos "curl"

  # forti-api, the header-only SDK: needed to compile, not at run time. Its release archive; bump it
  # to the latest forti-api release when one is cut.
  resource "forti-api" do
    url "https://github.com/valkyrianlabs/forti-api/releases/download/v1.3.0/forti-api-1.3.0.tar.gz"
    sha256 "218cb631522250bf95182212d88eaa9c4f2d494cd66d6e8d2b236eb1c356ae83"
  end

  def install
    # The SDK's headers and pkg-config file go into the build tree only, where dependency('forti-api')
    # finds them; none of it reaches the keg.
    resource("forti-api").stage do
      system "meson", "setup", "build", "-Dtests=disabled", *std_meson_args(prefix: buildpath/"forti-api-sdk")
      system "meson", "install", "-C", "build"
    end
    ENV.prepend_path "PKG_CONFIG_PATH", buildpath/"forti-api-sdk/share/pkgconfig"

    # std_meson_args sets --buildtype=release and --wrap-mode=nofallback (stricter than nodownload):
    # forti-api always comes from the resource above, never from subprojects/forti-api.wrap.
    # optimization=3 is meson.build's release profile, repeated so it holds whatever the build type;
    # strip=true installs the binary without its symbol table (24 MB -> 12 MB).
    # The tests need GoogleTest and run in CI; the `test do` block exercises the installed binary.
    system "meson", "setup", "build", "-Dtests=disabled", "-Doptimization=3", "-Dstrip=true", *std_meson_args
    system "meson", "compile", "-C", "build"
    system "meson", "install", "-C", "build"
  end

  test do
    assert_match "forti #{version}", shell_output("#{bin}/forti --version")

    # Offline: the resource catalog is compiled in, so no profile or device is needed.
    ENV["FORTI_HOME"] = (testpath/"forti").to_s
    output = JSON.parse(shell_output("#{bin}/forti --json discover firewall/address"))
    assert output["ok"]
    assert_includes output["data"]["fields"].map { |field| field["name"] }, "subnet"

    # Shell completion: meson installs it under share/, which Homebrew links into its prefix (bash
    # through bash-completion@2, zsh through site-functions, fish through vendor_completions.d).
    assert_path_exists share/"bash-completion/completions/forti"
    assert_path_exists zsh_completion/"_forti"
    assert_path_exists fish_completion/"forti.fish"
    assert_equal "get\n", shell_output("#{bin}/forti __complete commands ge")
  end
end
