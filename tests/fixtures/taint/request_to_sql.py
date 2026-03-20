# Tainted: request.args flows to cursor.execute (SQL injection)
# Note: uses request.args() not request.args.get() because the taint
# tracker matches exact function names from TAINT_SOURCES
query = request.args()
cursor.execute(query)
