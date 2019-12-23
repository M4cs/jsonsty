store_template = """\
    <fieldset>
      <div style="display: flex; align-items: center; justify-content: center;">
        <button class="button" id="{store_name_url}_edit" style="margin-top: 1rem; display: inline-block;" onclick="changeTextarea(document.getElementById('{store_name_url}'));changeSavebutton(document.getElementById('{store_name_url}_button'));changeCancelbutton(this);">Edit Store</button>
      </div>
      <form action="/stores/{store_name_url}/edit" method="POST">
      <details style="display: flex; flex-direction: column; align-items: flex-start; background-color: #161f27; padding: 10px 10px 10px; margin: 1em 0; border-radius: 6px; overflow: hidden;">
        <summary><b>Name:</b> {store_name}</summary>
        <textarea name="data" id="{store_name_url}" style="margin-top: 2px;" readonly>{data}</textarea>
      </details>
      <div style="display: flex; align-items: center; justify-content: center;">
        <button type="submit" class="button" id="{store_name_url}_button" disabled>Save Store</button>
        </form>
        <form action="/stores/{store_name_url}/delete" style="display: inline-block;" method="GET">
          <button type="submit" class="button" style="color: red;">Delete Store</button>
        </form>
      </div>
    </fieldset>"""
