using System.ComponentModel;
using System.Globalization;
using ModelContextProtocol.Server;
using OpenEtradeMcp.Contracts;
namespace OpenEtradeMcp.Server;
[McpServerToolType]
public sealed class ReadTools(GatewayAdapter adapter)
{
    [McpServerTool(Name = "listAccounts"), Description("Production read: listAccounts.")]
    public Task<string> listAccounts()
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.listAccounts, args));
    }
    [McpServerTool(Name = "getAccountBalance"), Description("Production read: getAccountBalance.")]
    public Task<string> getAccountBalance(string accountIdKey, string instType, string? accountType = null, bool? realTimeNAV = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["accountIdKey"] = accountIdKey;
        args["instType"] = instType;
        if (accountType != null) args["accountType"] = accountType;
        if (realTimeNAV != null) args["realTimeNAV"] = realTimeNAV.Value.ToString().ToLowerInvariant();
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.getAccountBalance, args));
    }
    [McpServerTool(Name = "getPortfolio"), Description("Production read: getPortfolio.")]
    public Task<string> getPortfolio(string accountIdKey, long? count = null, string? sortBy = null, string? sortOrder = null, long? pageNumber = null, string? marketSession = null, bool? totalsRequired = null, bool? lotsRequired = null, string? view = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["accountIdKey"] = accountIdKey;
        if (count != null) args["count"] = count.Value.ToString(CultureInfo.InvariantCulture);
        if (sortBy != null) args["sortBy"] = sortBy;
        if (sortOrder != null) args["sortOrder"] = sortOrder;
        if (pageNumber != null) args["pageNumber"] = pageNumber.Value.ToString(CultureInfo.InvariantCulture);
        if (marketSession != null) args["marketSession"] = marketSession;
        if (totalsRequired != null) args["totalsRequired"] = totalsRequired.Value.ToString().ToLowerInvariant();
        if (lotsRequired != null) args["lotsRequired"] = lotsRequired.Value.ToString().ToLowerInvariant();
        if (view != null) args["view"] = view;
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.getPortfolio, args));
    }
    [McpServerTool(Name = "listTransactions"), Description("Production read: listTransactions.")]
    public Task<string> listTransactions(string accountIdKey, string? startDate = null, string? endDate = null, string? sortOrder = null, string? marker = null, long? count = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["accountIdKey"] = accountIdKey;
        if (startDate != null) args["startDate"] = startDate;
        if (endDate != null) args["endDate"] = endDate;
        if (sortOrder != null) args["sortOrder"] = sortOrder;
        if (marker != null) args["marker"] = marker;
        if (count != null) args["count"] = count.Value.ToString(CultureInfo.InvariantCulture);
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.listTransactions, args));
    }
    [McpServerTool(Name = "getTransactionDetails"), Description("Production read: getTransactionDetails.")]
    public Task<string> getTransactionDetails(string accountIdKey, long transactionId, string? storeId = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["accountIdKey"] = accountIdKey;
        args["transactionId"] = transactionId.ToString(CultureInfo.InvariantCulture);
        if (storeId != null) args["storeId"] = storeId;
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.getTransactionDetails, args));
    }
    [McpServerTool(Name = "getQuotes"), Description("Production read: getQuotes.")]
    public Task<string> getQuotes(string symbols, string? detailFlag = null, bool? requireEarningsDate = null, bool? overrideSymbolCount = null, bool? skipMiniOptionsCheck = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["symbols"] = symbols;
        if (detailFlag != null) args["detailFlag"] = detailFlag;
        if (requireEarningsDate != null) args["requireEarningsDate"] = requireEarningsDate.Value.ToString().ToLowerInvariant();
        if (overrideSymbolCount != null) args["overrideSymbolCount"] = overrideSymbolCount.Value.ToString().ToLowerInvariant();
        if (skipMiniOptionsCheck != null) args["skipMiniOptionsCheck"] = skipMiniOptionsCheck.Value.ToString().ToLowerInvariant();
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.getQuotes, args));
    }
    [McpServerTool(Name = "lookupProduct"), Description("Production read: lookupProduct.")]
    public Task<string> lookupProduct(string search)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["search"] = search;
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.lookupProduct, args));
    }
    [McpServerTool(Name = "getOptionChains"), Description("Production read: getOptionChains.")]
    public Task<string> getOptionChains(string symbol, long? expiryYear = null, long? expiryMonth = null, long? expiryDay = null, double? strikePriceNear = null, long? noOfStrikes = null, bool? includeWeekly = null, bool? skipAdjusted = null, string? optionCategory = null, string? chainType = null, string? priceType = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["symbol"] = symbol;
        if (expiryYear != null) args["expiryYear"] = expiryYear.Value.ToString(CultureInfo.InvariantCulture);
        if (expiryMonth != null) args["expiryMonth"] = expiryMonth.Value.ToString(CultureInfo.InvariantCulture);
        if (expiryDay != null) args["expiryDay"] = expiryDay.Value.ToString(CultureInfo.InvariantCulture);
        if (strikePriceNear != null) args["strikePriceNear"] = strikePriceNear.Value.ToString(CultureInfo.InvariantCulture);
        if (noOfStrikes != null) args["noOfStrikes"] = noOfStrikes.Value.ToString(CultureInfo.InvariantCulture);
        if (includeWeekly != null) args["includeWeekly"] = includeWeekly.Value.ToString().ToLowerInvariant();
        if (skipAdjusted != null) args["skipAdjusted"] = skipAdjusted.Value.ToString().ToLowerInvariant();
        if (optionCategory != null) args["optionCategory"] = optionCategory;
        if (chainType != null) args["chainType"] = chainType;
        if (priceType != null) args["priceType"] = priceType;
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.getOptionChains, args));
    }
    [McpServerTool(Name = "getOptionExpireDates"), Description("Production read: getOptionExpireDates.")]
    public Task<string> getOptionExpireDates(string symbol, string? expiryType = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["symbol"] = symbol;
        if (expiryType != null) args["expiryType"] = expiryType;
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.getOptionExpireDates, args));
    }
    [McpServerTool(Name = "listOrders"), Description("Production read: listOrders.")]
    public Task<string> listOrders(string accountIdKey, string? marker = null, long? count = null, string? status = null, string? fromDate = null, string? toDate = null, string? symbol = null, string? securityType = null, string? transactionType = null, string? marketSession = null)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        args["accountIdKey"] = accountIdKey;
        if (marker != null) args["marker"] = marker;
        if (count != null) args["count"] = count.Value.ToString(CultureInfo.InvariantCulture);
        if (status != null) args["status"] = status;
        if (fromDate != null) args["fromDate"] = fromDate;
        if (toDate != null) args["toDate"] = toDate;
        if (symbol != null) args["symbol"] = symbol;
        if (securityType != null) args["securityType"] = securityType;
        if (transactionType != null) args["transactionType"] = transactionType;
        if (marketSession != null) args["marketSession"] = marketSession;
        return adapter.ReadAsync(new ReadRequest(1, ReadOperation.listOrders, args));
    }
}
