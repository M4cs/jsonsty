store_template = """\
    <details style="display: flex; flex-direction: column; align-items: flex-start; background-color: #212121; padding: 10px 10px 10px; margin: 1em 0; border-radius: 6px; overflow: hidden;">
      <summary>{store_name}</summary>
      <p><code>{data}</code></p>
    </details>
    <form action="/stores/{store_name}/delete" method="GET">
      <button type="submit" class="button">Delete Store</button>
    </form>"""