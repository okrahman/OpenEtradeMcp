ARG SDK_IMAGE
ARG RUNTIME_IMAGE
FROM ${SDK_IMAGE} AS build
ARG SERVICE
WORKDIR /source
COPY Directory.Build.props Directory.Packages.props ./
COPY src ./src
RUN dotnet publish src/OpenEtradeMcp.${SERVICE}/OpenEtradeMcp.${SERVICE}.csproj -f net10.0 -c Release -o /out /p:UseAppHost=false
FROM ${RUNTIME_IMAGE}
ARG SERVICE
WORKDIR /app
COPY --from=build /out/ /app/
COPY --chmod=0555 deploy/start.sh /app/start.sh
ENV SERVICE=${SERVICE} DOTNET_EnableDiagnostics=0
USER 10001:10001
ENTRYPOINT ["/app/start.sh"]
