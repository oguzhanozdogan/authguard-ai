from parser import parse_sarif

results = parse_sarif("results.sarif")

print("Total findings:", len(results))
print()

for r in results:
    print(r)
