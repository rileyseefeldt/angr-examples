import pstats

p = pstats.Stats("prof/combined.prof").sort_stats("cumulative")
p.print_stats(80)
