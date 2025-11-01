#!/usr/bin/env bash
failures=()

while IFS= read -r dir; do
  echo "==> Entering $dir"
  if ! (cd "$dir" && make test); then
    echo "❌ $dir failed"
    failures+=("$dir")
  else
    echo "✅ $dir passed"
  fi
done < <(find . -type f -name Makefile -exec dirname {} \;)

echo
echo "======================"
if [ ${#failures[@]} -eq 0 ]; then
  echo "✅ All tests passed"
else
  echo "❌ The following directories failed:"
  printf ' - %s\n' "${failures[@]}"
  exit 1
fi

