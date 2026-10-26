defmodule Samly.HTMLTest do
  use ExUnit.Case, async: true

  alias Samly.HTML

  describe "escape_attribute/1" do
    test "escapes HTML delimiters and both quote styles" do
      assert HTML.escape_attribute(~s(<a title="Bob's & Co">)) == "&lt;a title=&quot;Bob&#39;s &amp; Co&quot;&gt;"
    end

    test "escapes literal entities rather than interpreting input as trusted HTML" do
      assert HTML.escape_attribute("&quot;&lt;&#39;") == "&amp;quot;&amp;lt;&amp;#39;"
    end

    test "preserves Unicode and text without special characters" do
      assert HTML.escape_attribute("雪 café /sso/path") == "雪 café /sso/path"
      assert HTML.escape_attribute("") == ""
    end

    test "retains existing callers' string conversion for charlists and nil" do
      assert HTML.escape_attribute(~c"/sso?a=1&b=2") == "/sso?a=1&amp;b=2"
      assert HTML.escape_attribute(nil) == ""
    end
  end
end
