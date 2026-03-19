export const getVirusTotalUrl = (value, type) => {
  const paths = {
    domain: `https://www.virustotal.com/gui/domain/${value}`,
    ip:     `https://www.virustotal.com/gui/ip-address/${value}`,
    url:    `https://www.virustotal.com/gui/url/${btoa(value).replace(/=+$/, '')}`,
    hash:   `https://www.virustotal.com/gui/file/${value}`,
  };
  return paths[type] || `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
};
